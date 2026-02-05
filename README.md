# SCO to SCB Converter

Converts old .sco mesh files to .scb format for League of Legends mods.

## Download

Get `sco_fixer.exe` from the [dist](dist/) folder.

## Usage

Drag and drop onto the exe:
- `.fantome` files
- `.wad.client` files
- `.sco` files
- Folders containing `.fantome` files
- Folders containing loose `.sco` and `.bin` files
- Folders containing multiple skin subfolders

The tool will:
1. Convert all `.sco` files to `.scb`
2. Update `.bin` file references from `.sco` to `.scb`
3. Update WAD chunk hashes accordingly

## Why?

Some old mods use `.sco` meshes which aren't supported anymore. This tool batch converts them to the newer `.scb` format.


has logic from : 

# Pyritofile

Pyritofile is a Python library designed to read and manipulate basic league of legends files.
It is originally from [LtMAO](https://github.com/tarngaina/LtMAO/tree/master/src/LtMAO/pyRitoFile) project made by [Tarngaina](https://github.com/tarngaina) then published by me (GuiSaiUwU) to be used as a python package.

## Installation

Requires python **3.10** or higher.
Since its published in [PyPI](https://pypi.org/project/pyritofile/) to install its only required one simple CLI command:

```sh
pip install pyritofile
```

## Small Example Usage

To use pyritofile, you first need to import the class you want to use and instantiate, then you fill the data by using the read() method.

```python
from pyritofile import SKN

skn_file = SKN()
skn_file.read('Path/To/File.skn')
print(skn_file.__json__())
```

# Extra:
- [LeagueToolKit](https://github.com/LeagueToolkit/LeagueToolkit)
- [LtMAO](https://github.com/tarngaina/LtMAO)
