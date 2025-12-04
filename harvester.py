import os
import subprocess
import magic
import json
import shutil

class Harvester:
    def __init__(self, workspace_dir="./workspace"):
        self.workspace_dir = os.path.abspath(workspace_dir)
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir)

    def run_command(self, command):
        """Helper to run shell commands."""
        try:
            # Using shell=False for security, but command is a list
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(f"Error executing: {' '.join(command)}")
            print(e.stderr.decode())

    def unpack_firmware(self, firmware_path):
        """Recursively unpacks firmware using binwalk."""
        print(f"[\u26cf\ufe0f] Harvester: Unpacking {firmware_path}...")
        
        # Clean workspace if needed or create a specific subdir
        fw_name = os.path.basename(firmware_path)
        unpack_dir = os.path.join(self.workspace_dir, f"{fw_name}_extracted")
        
        if os.path.exists(unpack_dir):
            shutil.rmtree(unpack_dir)
        os.makedirs(unpack_dir)

        # Copy firmware to workspace to avoid messing with original location
        target_file = os.path.join(unpack_dir, fw_name)
        shutil.copy(firmware_path, target_file)

        # Run binwalk -Me --directory {unpack_dir} {target_file}
        # -M: Matryoshka (recursive), -e: extract, --directory: output dir
        cmd = ["binwalk", "-Me", "--directory", unpack_dir, target_file]
        
        # Check if binwalk is installed
        if shutil.which("binwalk") is None:
            print("Error: binwalk is not installed or not in PATH.")
            return None

        self.run_command(cmd)
        
        # The extraction usually creates a directory starting with '_'
        # We return the root unpack directory to search within
        return unpack_dir

    def find_binaries(self, search_dir):
        """Crawls the directory to find candidate binaries."""
        print(f"[\u1f50d] Harvester: Scanning for binaries in {search_dir}...")
        candidate_binaries = []
        
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self._is_candidate(file_path):
                    candidate_binaries.append(file_path)
                    
        return candidate_binaries

    def _is_candidate(self, file_path):
        """Filters files using python-magic."""
        # Skip symlinks to avoid loops or duplicates
        if os.path.islink(file_path):
            return False

        try:
            # Use magic to get file type
            file_type = magic.from_file(file_path)
            
            # Check for specific executable types
            if "ELF" in file_type:
                return True
            if "PE32" in file_type or "PE32+" in file_type:
                return True
            if "Mach-O" in file_type:
                return True
            if "u-boot" in file_type.lower():
                return True
            
            # Check for files with no extension but executable code signatures
            if "executable" in file_type.lower():
                return True

            # Additional check: Files with no extension that are not text
            filename = os.path.basename(file_path)
            if "." not in filename:
                mime_type = magic.from_file(file_path, mime=True)
                if "application/x-executable" in mime_type or "application/x-sharedlib" in mime_type:
                    return True

        except Exception as e:
            # print(f"Error checking {file_path}: {e}")
            pass
            
        return False

    def harvest(self, firmware_path):
        """Main execution method."""
        extracted_path = self.unpack_firmware(firmware_path)
        if not extracted_path:
            return []
        
        binaries = self.find_binaries(extracted_path)
        print(f"[\u2705] Harvester: Found {len(binaries)} candidate binaries.")
        return binaries

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python harvester.py <firmware_file>")
    else:
        harvester = Harvester()
        bins = harvester.harvest(sys.argv[1])
        print(json.dumps(bins, indent=4))
