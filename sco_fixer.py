"""
SCO to SCB Fixer - Drag and drop .fantome files to convert all SCO to SCB
Fast implementation with parallel processing
"""
import sys
import os
import re
import subprocess
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pyRitoFile.wad import WAD, WADChunk, WADHasher
from pyRitoFile.stream import BytesStream
from pyRitoFile.so import SO, SOFlag

# Number of parallel workers
NUM_WORKERS = 4


def resolve_shortcut(path):
    """Resolve a Windows shortcut (.lnk) to its target path."""
    if not path.lower().endswith('.lnk'):
        return path

    try:
        # Use PowerShell to resolve the shortcut
        result = subprocess.run(
            ['powershell', '-Command',
             f'(New-Object -ComObject WScript.Shell).CreateShortcut("{path}").TargetPath'],
            capture_output=True, text=True, timeout=5
        )
        target = result.stdout.strip()
        if target and os.path.exists(target):
            print(f"Resolved shortcut: {os.path.basename(path)} -> {target}")
            return target
    except Exception:
        pass

    return path


def convert_sco_bytes_to_scb(sco_data):
    """Convert SCO bytes to SCB bytes in memory."""
    # Normalize line endings (Windows -> Unix)
    sco_data = sco_data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')

    so = SO()
    so.read_sco(sco_data, raw=True)

    # Set defaults for SCB
    if so.flags is None:
        so.flags = SOFlag.HasLocalOriginLocatorAndPivot if so.pivot else SOFlag.HasVcp
    if so.vertex_type is None:
        so.vertex_type = 0

    return so.write_scb(None, raw=True)


def process_wad(wad_bytes):
    """Process WAD bytes: convert SCO to SCB and update bin references."""
    wad = WAD()
    wad.read(wad_bytes, raw=True)

    # Collect all chunk data
    chunk_data_map = {}  # hash -> data
    sco_chunks = {}      # hash -> chunk
    bin_chunks = {}      # hash -> chunk
    other_chunks = {}    # hash -> chunk

    with BytesStream.reader(wad_bytes, raw=True) as bs:
        for chunk in wad.chunks:
            chunk.read_data(bs)
            chunk_data_map[chunk.hash] = chunk.data

            if chunk.extension == 'sco':
                sco_chunks[chunk.hash] = chunk
            elif chunk.extension == 'bin':
                bin_chunks[chunk.hash] = chunk
            else:
                other_chunks[chunk.hash] = chunk

    if not sco_chunks:
        print("  No SCO files found in WAD")
        return wad_bytes

    # Find all .sco paths in bin files
    sco_path_pattern = re.compile(rb'([A-Za-z0-9_/]+\.sco)', re.IGNORECASE)
    sco_paths = set()

    for chunk_hash, chunk in bin_chunks.items():
        matches = sco_path_pattern.findall(chunk.data)
        for m in matches:
            sco_paths.add(m.decode())

    print(f"  Found {len(sco_paths)} SCO path references in bins")

    # Build hash mapping: old_hash -> (new_hash, new_path)
    hash_mapping = {}
    for path in sco_paths:
        old_hash = WADHasher.raw_to_hex(path)
        new_path = path[:-4] + '.scb'  # Replace .sco with .scb
        new_hash = WADHasher.raw_to_hex(new_path)
        hash_mapping[old_hash] = (new_hash, new_path)

    # Convert SCO chunks to SCB and update hashes
    new_chunk_data = {}
    converted_count = 0

    for old_hash, chunk in sco_chunks.items():
        if old_hash in hash_mapping:
            new_hash, new_path = hash_mapping[old_hash]
            try:
                scb_data = convert_sco_bytes_to_scb(chunk.data)
                new_chunk_data[new_hash] = scb_data
                converted_count += 1
                print(f"  Converted: {new_path}")
            except Exception as e:
                print(f"  Error converting {old_hash}: {e}")
                new_chunk_data[old_hash] = chunk.data  # Keep original
        else:
            # SCO not referenced in bins, keep as-is
            new_chunk_data[old_hash] = chunk.data

    # Update bin files: replace .sco with .scb
    for chunk_hash, chunk in bin_chunks.items():
        updated_data = chunk.data.replace(b'.sco', b'.scb').replace(b'.SCO', b'.SCB')
        new_chunk_data[chunk_hash] = updated_data

    # Add other chunks unchanged
    for chunk_hash, chunk in other_chunks.items():
        new_chunk_data[chunk_hash] = chunk.data

    print(f"  Converted {converted_count} SCO files to SCB")

    # Rebuild WAD
    chunk_hashes = list(new_chunk_data.keys())
    chunk_datas = [new_chunk_data[h] for h in chunk_hashes]

    new_wad = WAD()
    new_wad.chunks = [WADChunk.default() for _ in range(len(chunk_hashes))]

    # Write WAD header first
    wad_header = new_wad.write(None, raw=True)

    with BytesStream.writer(None, raw=True) as bs:
        bs.write(wad_header)
        for idx, chunk in enumerate(new_wad.chunks):
            chunk.write_data(bs, idx, chunk_hashes[idx], chunk_datas[idx],
                           previous_chunks=(new_wad.chunks[i] for i in range(idx)))
            chunk.free_data()
        return bs.raw()


def process_fantome(fantome_path, verbose=True):
    """Process a fantome file and fix all SCO to SCB."""
    if verbose:
        print(f"\nProcessing: {fantome_path}")

    with open(fantome_path, 'rb') as f:
        zip_file = ZipFile(f, 'r')

        wads = {}
        other_files = {}

        for info in zip_file.infolist():
            if info.is_dir():
                continue

            data = zip_file.read(info)
            if info.filename.lower().endswith('.wad.client'):
                wads[info.filename] = data
            else:
                other_files[info.filename] = data

        zip_file.close()

    if not wads:
        print("  No WAD files found in fantome")
        return

    # Process each WAD
    processed_wads = {}
    for wad_name, wad_data in wads.items():
        print(f"  Processing WAD: {wad_name}")
        processed_wads[wad_name] = process_wad(wad_data)

    # Write output
    output_buffer = BytesIO()
    with ZipFile(output_buffer, 'w', ZIP_DEFLATED) as out_zip:
        for name, data in processed_wads.items():
            out_zip.writestr(name, data)
        for name, data in other_files.items():
            out_zip.writestr(name, data)

    # Overwrite original
    with open(fantome_path, 'wb') as f:
        f.write(output_buffer.getvalue())

    print(f"  Done! Saved to: {fantome_path}")


def check_sco_status(fantome_path):
    """Check SCO status in fantome. Returns (has_sco_chunks, has_sco_refs)."""
    try:
        sco_path_pattern = re.compile(rb'[A-Za-z0-9_/]+\.sco', re.IGNORECASE)
        has_sco_chunks = False
        has_sco_refs = False

        with open(fantome_path, 'rb') as f:
            with ZipFile(f, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.lower().endswith('.wad.client'):
                        wad_data = zf.read(info)
                        wad = WAD()
                        wad.read(wad_data, raw=True)

                        with BytesStream.reader(wad_data, raw=True) as bs:
                            for chunk in wad.chunks:
                                chunk.read_data(bs)
                                if chunk.extension == 'sco':
                                    has_sco_chunks = True
                                elif chunk.extension == 'bin':
                                    if sco_path_pattern.search(chunk.data):
                                        has_sco_refs = True

                        if has_sco_chunks and has_sco_refs:
                            return (True, True)  # Early exit

        return (has_sco_chunks, has_sco_refs)
    except:
        return (True, True)  # Process anyway if check fails


def process_fantome_worker(fantome_path):
    """Worker function for parallel processing. Returns (path, success, message)."""
    try:
        # Check SCO status
        has_sco_chunks, has_sco_refs = check_sco_status(fantome_path)

        if not has_sco_chunks:
            return (fantome_path, True, "skipped (no SCO files)")

        if not has_sco_refs:
            return (fantome_path, True, "skipped (already uses SCB)")

        process_fantome(fantome_path, verbose=False)
        return (fantome_path, True, "fixed")
    except Exception as e:
        return (fantome_path, False, str(e))


def process_raw_folder(folder_path, verbose=False):
    """Process a raw mod folder with loose .sco and .bin files.
    Returns (converted_count, bins_updated, error_msg or None)
    """
    sco_files = []
    bin_files = []

    # Find all .sco and .bin files
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            full_path = os.path.join(root, f)
            if f.lower().endswith('.sco'):
                sco_files.append(full_path)
            elif f.lower().endswith('.bin'):
                bin_files.append(full_path)

    if not sco_files and not bin_files:
        return (0, 0, "no .sco or .bin files")

    converted = 0
    errors = []

    # Convert SCO files to SCB
    for sco_path in sco_files:
        try:
            with open(sco_path, 'rb') as f:
                sco_data = f.read()

            scb_data = convert_sco_bytes_to_scb(sco_data)

            # Write SCB file (same name, different extension)
            scb_path = sco_path[:-4] + '.scb'
            with open(scb_path, 'wb') as f:
                f.write(scb_data)

            # Delete original SCO
            os.remove(sco_path)
            converted += 1
        except Exception as e:
            errors.append(f"{os.path.basename(sco_path)}: {e}")

    # Update bin files: replace .sco with .scb
    bins_updated = 0
    for bin_path in bin_files:
        try:
            with open(bin_path, 'rb') as f:
                data = f.read()

            if b'.sco' in data or b'.SCO' in data:
                updated = data.replace(b'.sco', b'.scb').replace(b'.SCO', b'.SCB')
                with open(bin_path, 'wb') as f:
                    f.write(updated)
                bins_updated += 1
        except Exception as e:
            errors.append(f"{os.path.basename(bin_path)}: {e}")

    error_msg = "; ".join(errors) if errors else None
    return (converted, bins_updated, error_msg)


def is_raw_mod_folder(folder_path):
    """Check if folder contains raw .sco or .bin files (not fantomes)."""
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            if f.lower().endswith('.sco') or f.lower().endswith('.bin'):
                return True
            if f.lower().endswith('.fantome') or f.lower().endswith('.zip'):
                return False  # It's a fantome folder
    return False


def find_skin_subfolders(parent_folder):
    """Find subfolders that are raw mod folders (skin collection support)."""
    skin_folders = []

    # Check immediate subfolders only (not recursive)
    for item in os.listdir(parent_folder):
        subfolder = os.path.join(parent_folder, item)
        if os.path.isdir(subfolder):
            # Check if this subfolder has .sco or .bin files
            has_mod_files = False
            for root, dirs, files in os.walk(subfolder):
                for f in files:
                    if f.lower().endswith('.sco') or f.lower().endswith('.bin'):
                        has_mod_files = True
                        break
                if has_mod_files:
                    break

            if has_mod_files:
                skin_folders.append(subfolder)

    return skin_folders


def is_skin_collection_folder(folder_path):
    """Check if folder is a parent containing multiple skin subfolders."""
    # Check if the folder itself has .sco/.bin files directly
    direct_files = os.listdir(folder_path)
    for f in direct_files:
        if f.lower().endswith('.sco') or f.lower().endswith('.bin'):
            return False  # It's a raw mod folder itself, not a collection

    # Check if it has subfolders with raw mod files
    skin_folders = find_skin_subfolders(folder_path)
    return len(skin_folders) > 0


def find_fantomes_in_folder(folder_path):
    """Recursively find all .fantome files in a folder."""
    fantomes = []
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            if f.lower().endswith('.fantome') or f.lower().endswith('.zip'):
                fantomes.append(os.path.join(root, f))
    return fantomes


def main():
    if len(sys.argv) < 2:
        print("SCO to SCB Fixer")
        print("Drag and drop files or folders onto this exe")
        print("\nSupports:")
        print("  - .fantome files (packed mods)")
        print("  - Folders with .fantome files")
        print("  - Raw mod folders (loose .sco and .bin files)")
        print("  - Skin collection folders (parent folder with skin subfolders)")
        print("  - Single .sco files")
        print("  - Single .wad.client files")
        print("  - Windows shortcuts (.lnk) to any of the above")
        print("\nUsage: sco_fixer.exe <file.fantome> [folder] [file.sco] ...")
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass
        return

    # Collect all fantome files to process
    files_to_process = []
    raw_folders = []
    sco_converted = 0

    for arg in sys.argv[1:]:
        # Resolve shortcuts first
        arg = resolve_shortcut(arg)

        if os.path.isdir(arg):
            # Check if it's a skin collection folder (parent with skin subfolders)
            if is_skin_collection_folder(arg):
                skin_folders = find_skin_subfolders(arg)
                print(f"Found {len(skin_folders)} skin folder(s) in: {arg}")
                raw_folders.extend(skin_folders)
            # Check if it's a raw mod folder itself
            elif is_raw_mod_folder(arg):
                raw_folders.append(arg)
            else:
                fantomes = find_fantomes_in_folder(arg)
                if fantomes:
                    print(f"Found {len(fantomes)} fantome(s) in folder: {arg}")
                    files_to_process.extend(fantomes)
                else:
                    print(f"No fantome or raw mod files found in: {arg}")
        elif arg.lower().endswith('.fantome') or arg.lower().endswith('.zip'):
            if os.path.exists(arg):
                files_to_process.append(arg)
            else:
                print(f"File not found: {arg}")
        elif arg.lower().endswith('.sco'):
            # Single SCO file
            if os.path.exists(arg):
                try:
                    with open(arg, 'rb') as f:
                        sco_data = f.read()
                    scb_data = convert_sco_bytes_to_scb(sco_data)
                    scb_path = arg[:-4] + '.scb'
                    with open(scb_path, 'wb') as f:
                        f.write(scb_data)
                    os.remove(arg)
                    print(f"Converted: {arg} -> {scb_path}")
                    sco_converted += 1
                except Exception as e:
                    print(f"Error converting {arg}: {e}")
        elif arg.lower().endswith('.wad.client') or arg.lower().endswith('.wad'):
            # Single WAD file
            if os.path.exists(arg):
                try:
                    print(f"Processing WAD: {os.path.basename(arg)}")
                    with open(arg, 'rb') as f:
                        wad_bytes = f.read()
                    new_wad_bytes = process_wad(wad_bytes)
                    with open(arg, 'wb') as f:
                        f.write(new_wad_bytes)
                    sco_converted += 1
                except Exception as e:
                    print(f"Error processing {arg}: {e}")
        else:
            print(f"Skipping (not a fantome, folder, or SCO): {arg}")

    # Process raw mod folders first
    if raw_folders:
        total = len(raw_folders)
        print(f"\nProcessing {total} raw mod folder(s)...\n")
        total_converted = 0
        total_bins = 0
        total_errors = 0

        for i, folder in enumerate(raw_folders, 1):
            folder_name = os.path.basename(folder)
            converted, bins_updated, error = process_raw_folder(folder)
            total_converted += converted
            total_bins += bins_updated

            if error and "no .sco" in error:
                print(f"[{i}/{total}] {folder_name} - skipped ({error})")
            elif error:
                total_errors += 1
                print(f"[{i}/{total}] {folder_name} - {converted} SCO, {bins_updated} bins (ERRORS: {error})")
            elif converted == 0:
                print(f"[{i}/{total}] {folder_name} - no SCO files to convert")
            else:
                print(f"[{i}/{total}] {folder_name} - {converted} SCO converted, {bins_updated} bins updated")

        print(f"\nResults: {total_converted} SCO files converted, {total_bins} bins updated, {total_errors} errors")

    if not files_to_process and not raw_folders and sco_converted == 0:
        print("\nNo files to process.")
    elif files_to_process:
        total = len(files_to_process)
        print(f"\nProcessing {total} fantome file(s)...\n")

        success = 0
        skipped = 0
        failed = 0

        for i, fantome_path in enumerate(files_to_process, 1):
            filename = os.path.basename(fantome_path)
            try:
                has_sco_chunks, has_sco_refs = check_sco_status(fantome_path)

                if not has_sco_chunks:
                    skipped += 1
                    print(f"[{i}/{total}] {filename} - skipped (no SCO files)")
                    continue
                if not has_sco_refs:
                    skipped += 1
                    print(f"[{i}/{total}] {filename} - skipped (already uses SCB)")
                    continue

                process_fantome(fantome_path, verbose=False)
                success += 1
                print(f"[{i}/{total}] {filename} - fixed")
            except Exception as e:
                failed += 1
                print(f"[{i}/{total}] {filename} - ERROR: {e}")

        print(f"\nResults: {success} fixed, {skipped} skipped, {failed} failed")

    print("\n" + "="*50)
    print("All done!")
    try:
        input("Press Enter to exit...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
