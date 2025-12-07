import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
print(os.getenv("GHIDRA_HOME"))
import shutil
print(shutil.which("binwalk"))