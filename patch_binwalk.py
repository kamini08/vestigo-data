import os

TARGET_FILE = "/home/kamini08/projects/cfg-extractor/venv/lib/python3.12/site-packages/binwalk/core/plugin.py"

NEW_IMPORT = """import os
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

def patch():
    with open(TARGET_FILE, 'r') as f:
        content = f.read()
    
    # Replace imports
    # We look for the block of imports to replace safely
    old_import_block = "import os\nimport imp\nimport inspect\nimport binwalk.core.common\nimport binwalk.core.settings\nfrom binwalk.core.compat import *\nfrom binwalk.core.exceptions import IgnoreFileException"
    
    if old_import_block not in content:
        print("Could not find import block. File might be already patched or different version.")
        # Fallback: simple string replace of 'import imp' if block match fails
        content = content.replace("import imp", "import importlib.machinery\nimport importlib.util")
        # Add helper function after imports (hacky but works for simple script)
        content = content.replace("from binwalk.core.exceptions import IgnoreFileException", "from binwalk.core.exceptions import IgnoreFileException\n\ndef _load_source(name, path):\n    loader = importlib.machinery.SourceFileLoader(name, path)\n    spec = importlib.util.spec_from_loader(loader.name, loader)\n    mod = importlib.util.module_from_spec(spec)\n    loader.exec_module(mod)\n    return mod\n")
    else:
        content = content.replace(old_import_block, NEW_IMPORT)

    # Replace usages
    content = content.replace("imp.load_source", "_load_source")
    
    with open(TARGET_FILE, 'w') as f:
        f.write(content)
    print("Patched binwalk/core/plugin.py successfully.")

    # --- Patch module.py ---
    MODULE_FILE = "/home/kamini08/projects/cfg-extractor/venv/lib/python3.12/site-packages/binwalk/core/module.py"
    with open(MODULE_FILE, 'r') as f:
        content = f.read()
    
    # Add imports at top
    if "import importlib.machinery" not in content:
        content = content.replace("import argparse", "import argparse\nimport importlib.machinery\nimport importlib.util")
        
    # Add helper function (if not exists)
    if "def _load_source(name, path):" not in content:
        content = content.replace("from binwalk.core.exceptions import *", "from binwalk.core.exceptions import *\n\ndef _load_source(name, path):\n    loader = importlib.machinery.SourceFileLoader(name, path)\n    spec = importlib.util.spec_from_loader(loader.name, loader)\n    mod = importlib.util.module_from_spec(spec)\n    loader.exec_module(mod)\n    return mod\n")

    # Replace local import imp
    content = content.replace("        import imp", "        # import imp")
    
    # Replace usage
    content = content.replace("imp.load_source", "_load_source")

    with open(MODULE_FILE, 'w') as f:
        f.write(content)
    print("Patched binwalk/core/module.py successfully.")

if __name__ == "__main__":
    patch()
