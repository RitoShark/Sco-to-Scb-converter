# SCO to SCB Converter

Converts old .sco mesh files to .scb format for League of Legends mods.

## Download

Get `sco_fixer.exe` from the [dist](dist/) folder.

## Usage

Drag and drop onto the exe:
- `.fantome` files
- `.sco` files
- Folders containing mods
- Folders containing multiple skin subfolders

The tool will:
1. Convert all `.sco` files to `.scb`
2. Update `.bin` file references from `.sco` to `.scb`
3. Update WAD chunk hashes accordingly

## Why?

Some old mods use `.sco` meshes which aren't supported anymore. This tool batch converts them to the newer `.scb` format.
