import os
import sys
import shutil
import json
import subprocess
import magic 
from unpack import automate_unpacking 

class IngestionModule:
    def __init__(self, output_base_dir="./analysis_workspace"):
        self.output_base_dir = os.path.abspath(output_base_dir)
        if not os.path.exists(self.output_base_dir):
            os.makedirs(self.output_base_dir)

    def _get_file_type(self, file_path):
        """Uses libmagic to get the true file type."""
        try:
            return magic.from_file(file_path)
        except Exception:
            return "Unknown"

    def _is_linux_fs(self, extracted_path):
        """Heuristic: Does this look like a Linux Filesystem?"""
        indicators = ["bin", "etc", "lib", "usr", "sbin"]
        hits = 0
        # Walk only the top few levels to save time
        for root, dirs, files in os.walk(extracted_path):
            # Check current directory names
            for dirname in dirs:
                if dirname in indicators:
                    hits += 1
            # Check for squashfs-root folder pattern which binwalk creates
            if "squashfs-root" in root:
                hits += 2
                
            if hits >= 2:
                return True
        return False
    
    def _check_for_bootloader(self, extracted_path):
        """
        Check for bootloader binaries in extracted firmware.
        Uses behavioral detection instead of hardcoded names to catch diverse bootloaders.
        """
        found_bootloaders = []
        seen_paths = set()
        
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                if file_path in seen_paths:
                    continue
                    
                try:
                    if not os.path.isfile(file_path):
                        continue
                        
                    file_size = os.path.getsize(file_path)
                    if file_size == 0 or file_size > 10 * 1024 * 1024:
                        continue
                    
                    # Skip obvious false positives
                    file_lower = file.lower()
                    # Skip text/metadata/script files
                    skip_extensions = ['.txt', '.sh', '.md', '.conf', '.list', '.control', 
                                      '.postinst', '.prerm', '.log', '.json', '.xml', '.html']
                    if any(file_lower.endswith(ext) for ext in skip_extensions):
                        continue
                    
                    # Skip common directories with false positives
                    skip_dirs = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.button/', 
                                '/usr/lib/opkg/', '/usr/share/doc/', '/var/log/']
                    if any(skip in root for skip in skip_dirs):
                        continue
                    
                    # Must be binary file
                    if not self._is_binary_file(file_path):
                        continue
                    
                    # Size check: bootloaders typically 4KB - 10MB
                    if file_size < 4096 or file_size > 10 * 1024 * 1024:
                        continue
                    
                    # Read file header for analysis
                    with open(file_path, 'rb') as f:
                        header = f.read(4096)
                    
                    # Check if it's an executable binary
                    if not self._looks_like_executable(header):
                        continue
                    
                    # Check for bootloader signatures in content
                    header_str = header.decode('latin-1', errors='ignore')
                    detection_result = self._detect_bootloader_type(header_str, file_lower)
                    
                    if detection_result:
                        found_bootloaders.append({
                            "type": detection_result["type"],
                            "file": file,
                            "path": file_path,
                            "size": file_size,
                            "reason": detection_result["reason"]
                        })
                        seen_paths.add(file_path)
                except Exception:
                    continue
        
        return found_bootloaders[:10]
    
    def _is_binary_file(self, file_path):
        """Check if file is binary (not text)"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(512)
                # Check for null bytes (strong indicator of binary)
                if b'\x00' in chunk:
                    return True
                # Check if most bytes are printable ASCII/UTF-8
                try:
                    chunk.decode('utf-8')
                    return False  # Successfully decoded as text
                except UnicodeDecodeError:
                    return True  # Not valid UTF-8, likely binary
        except:
            return False
    
    def _looks_like_executable(self, header):
        """Check if header looks like executable code"""
        if len(header) < 16:
            return False
        
        # Check for common executable magic bytes
        magic_bytes = [
            b'\x7fELF',           # ELF
            b'MZ',                # PE/DOS
            b'\xfe\xed\xfa\xce',  # Mach-O 32-bit
            b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit
            b'\xca\xfe\xba\xbe',  # Mach-O fat binary
        ]
        
        for magic in magic_bytes:
            if header.startswith(magic):
                return True
        
        # Check for ARM/MIPS/x86 instruction patterns (raw binaries)
        # Look for common instruction sequences
        if len(header) >= 256:
            # Check entropy - executable code has moderate-high entropy (0.6-0.9)
            unique_bytes = len(set(header[:256]))
            if unique_bytes > 80:  # Diverse byte distribution
                # Additional check: shouldn't be all zeros or all 0xFF
                if header[:256] != b'\x00' * 256 and header[:256] != b'\xff' * 256:
                    return True
        
        return False
    
    def _detect_bootloader_type(self, header_str, filename):
        """Detect bootloader type from file content and name"""
        bootloader_signatures = {
            "u-boot": {
                "strings": ["U-Boot", "Das U-Boot", "uboot", "=> ", "Hit any key to stop autoboot"],
                "keywords": ["u-boot", "uboot"]
            },
            "grub": {
                "strings": ["GRUB", "GNU GRUB", "grub>"],
                "keywords": ["grub"]
            },
            "cfe": {
                "strings": ["CFE", "Broadcom", "CFE version"],
                "keywords": ["cfe"]
            },
            "raspberry-pi": {
                "strings": ["Raspberry", "BCM", "start.elf", "bootcode"],
                "keywords": ["pieeprom", "bootcode", "start", "fixup", "vl805", "recovery.bin"]
            },
            "redboot": {
                "strings": ["RedBoot", "RedBoot>"],
                "keywords": ["redboot"]
            },
            "barebox": {
                "strings": ["barebox", "barebox>"],
                "keywords": ["barebox"]
            },
            "spl": {
                "strings": ["SPL", "Secondary Program Loader", "U-Boot SPL"],
                "keywords": ["mlo", "spl"]
            }
        }
        
        for bl_type, patterns in bootloader_signatures.items():
            # Check content signatures
            if any(sig in header_str for sig in patterns["strings"]):
                return {"type": bl_type, "reason": f"signature match: {bl_type}"}
            
            # Check filename patterns
            if any(keyword in filename for keyword in patterns["keywords"]):
                return {"type": bl_type, "reason": f"filename match: {bl_type}"}
        
        return None

    def _extract_ar_archive(self, ar_file_path, extract_dir):
        """Extract .o files from .a (ar) archive using ar command"""
        import subprocess
        
        try:
            print(f"    \u21B3 Extracting .a archive using ar command...")
            
            # Create extraction directory for .o files
            ar_extract_dir = os.path.join(extract_dir, "ar_extracted")
            if os.path.exists(ar_extract_dir):
                shutil.rmtree(ar_extract_dir)
            os.makedirs(ar_extract_dir)
            
            # Use ar to extract all files from the archive
            result = subprocess.run(
                ["ar", "x", ar_file_path],
                cwd=ar_extract_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                print(f"    \u26A0 ar extraction failed: {result.stderr}")
                return None, []
            
            # List extracted .o files
            extracted_objects = []
            if os.path.exists(ar_extract_dir):
                for filename in os.listdir(ar_extract_dir):
                    if filename.endswith('.o'):
                        full_path = os.path.join(ar_extract_dir, filename)
                        extracted_objects.append(full_path)
            
            if extracted_objects:
                print(f"    \u21B3 Extracted {len(extracted_objects)} object files from archive")
                return ar_extract_dir, extracted_objects
            else:
                print(f"    \u26A0 No .o files found in archive")
                return None, []
                
        except subprocess.TimeoutExpired:
            print(f"    \u26A0 ar extraction timed out")
            return None, []
        except FileNotFoundError:
            print(f"    \u26A0 ar command not found. Please install binutils.")
            return None, []
        except Exception as e:
            print(f"    \u26A0 ar extraction error: {e}")
            return None, []

    def process(self, input_file_path):
        print(f"[\u25B6] Module 1: Ingesting {os.path.basename(input_file_path)}...")
        
        report = {
            "status": "FAILED",
            "file_info": {"original_name": os.path.basename(input_file_path)},
            "extraction": {"was_extracted": False},
            "routing": {"decision": "UNKNOWN"}
        }

        # 1. Identification
        file_type = self._get_file_type(input_file_path)
        report["file_info"]["detected_type"] = file_type
        print(f"    \u21B3 Identified: {file_type}")

        # 2. Extraction (Binwalk)
        # Create a specific folder for this analysis
        analysis_dir = os.path.join(self.output_base_dir, report["file_info"]["original_name"] + "_analysis")
        if os.path.exists(analysis_dir): shutil.rmtree(analysis_dir)
        os.makedirs(analysis_dir)
        
        # Copy input file to analysis dir to keep original safe
        working_file = os.path.join(analysis_dir, os.path.basename(input_file_path))
        shutil.copy(input_file_path, working_file)

        print(f"    \u21B3 Running Recursive Extraction (this may take time)...")
        try:
            # Use the shared unpacker module
            extracted_full_path = automate_unpacking(working_file, analysis_dir)

            if extracted_full_path and os.path.exists(extracted_full_path) and len(os.listdir(extracted_full_path)) > 0:
                report["extraction"]["was_extracted"] = True
                report["extraction"]["extracted_path"] = extracted_full_path
                print(f"    \u21B3 Extraction Successful.")
                
                print(f"    \u21B3 Checking for bootloader...")
                bootloaders = self._check_for_bootloader(extracted_full_path)
                if bootloaders:
                    report["extraction"]["bootloaders_found"] = bootloaders
                    print(f"    \u21B3 Found {len(bootloaders)} bootloader(s)")
                    for bl in bootloaders[:3]:
                        print(f"      - {bl['type']}: {bl['file']}")
            else:
                print(f"    \u21B3 No files extracted.")
                
        except Exception as e:
            print(f"    \u26A0 Extraction Error: {e}")

        # 3. Routing Logic
        if "ELF" in file_type and "executable" in file_type:
            # It's a single binary, not a firmware image
            report["routing"]["decision"] = "PATH_A_BARE_METAL" # Or 'Direct Binary Analysis'
            report["routing"]["reason"] = "Input is a standalone ELF executable."
            
        elif input_file_path.endswith('.o') or ("ELF" in file_type and "relocatable" in file_type):
            # It's an object file (.o) - route to Path A
            report["routing"]["decision"] = "PATH_A_BARE_METAL"
            report["routing"]["reason"] = "Input is an object file (.o) - routing to bare metal analysis."
            
        elif input_file_path.endswith('.bin'):
            # Binary firmware files (.bin) - route to Path B for filesystem extraction
            # Check if extraction was successful to determine if it's a firmware image
            if report["extraction"]["was_extracted"] and report["extraction"].get("extracted_path"):
                # Successfully extracted - check for Linux filesystem
                if self._is_linux_fs(report["extraction"]["extracted_path"]):
                    report["routing"]["decision"] = "PATH_B_LINUX_FS"
                    report["routing"]["reason"] = "Binary firmware (.bin) extracted to Linux filesystem - routing to filesystem analysis."
                else:
                    # Extracted but no clear filesystem - could be bare metal firmware
                    report["routing"]["decision"] = "PATH_A_BARE_METAL"
                    report["routing"]["reason"] = "Binary firmware (.bin) extracted but no Linux FS found"
            else:
                # Extraction failed - encrypted or obfuscated firmware
                report["routing"]["decision"] = "PATH_C_HARD_TARGET"
                report["routing"]["reason"] = "Binary firmware (.bin) extraction failed"
            
        elif input_file_path.endswith('.a') or "archive" in file_type.lower():
            # Archive files (.a) - extract .o files using ar and route to Path A
            ar_extract_dir, extracted_objects = self._extract_ar_archive(working_file, analysis_dir)
            
            if extracted_objects:
                report["extraction"]["was_extracted"] = True
                report["extraction"]["extracted_path"] = ar_extract_dir
                report["extraction"]["extracted_objects"] = extracted_objects
                report["routing"]["decision"] = "PATH_A_BARE_METAL"
                report["routing"]["reason"] = f"Extracted {len(extracted_objects)} object files from .a archive - routing to bare metal analysis."
            else:
                report["routing"]["decision"] = "PATH_C_HARD_TARGET"
                report["routing"]["reason"] = "Failed to extract object files from .a archive."
            
        elif report["extraction"]["was_extracted"]:
            # Check if it extracted a File System or just junk
            if self._is_linux_fs(report["extraction"]["extracted_path"]):
                report["routing"]["decision"] = "PATH_B_LINUX_FS"
                report["routing"]["reason"] = "Found Linux FS structure (/bin, /etc)."
            else:
                # Extracted something, but no OS structure -> Likely Bare Metal / RTOS blobs
                report["routing"]["decision"] = "PATH_A_BARE_METAL"
                report["routing"]["reason"] = "Extracted data, but no Linux FS found. Treating as Bare Metal/RTOS."
                
        else:
            # Extraction failed. Is it encrypted?
            # Heuristic: Binwalk failed + High Entropy (implied) usually means encrypted
            # In a real tool, we'd calculate entropy here. Assuming extraction failure on non-trivial file = Encrypted
            report["routing"]["decision"] = "PATH_C_HARD_TARGET"
            report["routing"]["reason"] = "Extraction failed. File may be Encrypted, Obfuscated, or Unsupported."

        report["status"] = "COMPLETE"
        report["analysis_workspace"] = analysis_dir
        
        # Add next steps based on routing decision
        if report["routing"]["decision"] == "PATH_A_BARE_METAL":
            report["next_steps"] = ["Extract features using Ghidra", "Classify cryptographic functions"]
        elif report["routing"]["decision"] == "PATH_B_LINUX_FS":
            report["next_steps"] = ["Scan filesystem for crypto libraries", "Analyze binaries in filesystem"]
        elif report["routing"]["decision"] == "PATH_C_HARD_TARGET":
            report["next_steps"] = ["Perform entropy analysis", "Attempt decryption"]
        else:
            report["next_steps"] = ["Manual analysis required"]
        
        print(f"[\u2713] Routing to: {report['routing']['decision']}")
        return report

# CLI Wrapper for testing
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <firmware_file>")
        sys.exit(1)
    
    module = IngestionModule()
    result = module.process(sys.argv[1])
    print(json.dumps(result, indent=4))
