import os

PLUGIN_FILE = "/home/kamini08/projects/cfg-extractor/venv/lib/python3.12/site-packages/binwalk/core/plugin.py"

CORRECT_HEADER = """# Core code for supporting and managing plugins.

import os
import inspect
import binwalk.core.common
import binwalk.core.settings
from binwalk.core.compat import *
from binwalk.core.exceptions import IgnoreFileException
import importlib.machinery
import importlib.util

def _load_source(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

"""

def repair():
    with open(PLUGIN_FILE, 'r') as f:
        content = f.read()
    
    # Find where the class definition starts
    split_marker = "class Plugin(object):"
    if split_marker not in content:
        print("Error: Could not find 'class Plugin(object):' marker.")
        return

    parts = content.split(split_marker)
    if len(parts) < 2:
        print("Error: Split failed.")
        return
        
    # Keep everything after the marker
    rest_of_file = split_marker + parts[1]
    
    # Combine correct header with rest of file
    new_content = CORRECT_HEADER + rest_of_file
    
    with open(PLUGIN_FILE, 'w') as f:
        f.write(new_content)
    print("Repaired binwalk/core/plugin.py successfully.")

if __name__ == "__main__":
    repair()
