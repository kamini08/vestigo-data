import os
import subprocess
import sys
import shutil

"""
Common Firmware File Systems and Formats:

1. SquashFS - Most common in routers, IoT devices (read-only)
   - Variants: Little-endian, Big-endian, different compression (GZIP, LZMA, LZO, XZ)
   - Tool: sasquatch

2. UBIFS (Unsorted Block Image File System) - NAND flash devices
   - Used in: Android devices, embedded Linux systems
   - Tool: ubireader, ubi_reader

3. JFFS2 (Journalling Flash File System v2) - NOR flash devices
   - Used in: Older routers, embedded systems
   - Tool: jefferson, jffs2dump

4. YAFFS2 (Yet Another Flash File System) - NAND flash
   - Used in: Android devices, some embedded systems
   - Tool: unyaffs, yaffs2utils

5. CRAMFS (Compressed ROM File System) - Compressed read-only
   - Used in: Older embedded systems
   - Tool: cramfsck

6. ROMFS (ROM File System) - Simple read-only
   - Used in: Minimal embedded systems
   - Tool: romfs

7. initramfs/initrd - Initial RAM file systems
   - Used in: Boot loaders, kernel initialization
   - Tool: cpio, gzip

8. FAT/VFAT - DOS/Windows file systems
   - Used in: Boot partitions, storage devices
   - Tool: standard mount

9. ext2/ext3/ext4 - Linux file systems
   - Used in: Linux-based devices
   - Tool: standard mount

10. Proprietary formats - Vendor-specific
    - Examples: Broadcom CFE, U-Boot images
    - Tool: Custom extractors or reverse engineering
"""


def run_grep(pattern, search_path, description):
    print(f"\n[+] Searching for {description}...")
    try:
        # grep options: -r (recursive), -i (ignore case), -n (line number), -I (skip binary)
        # We use a list for the command to avoid shell injection
        cmd = ["grep", "-r", "-i", "-n", "-I", pattern, search_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout:
            lines = result.stdout.strip().split("\n")
            print(f"    FOUND {len(lines)} matches. First few:")
            for line in lines[:5]:
                print(f"    -> {line.strip()[:150]}...")  # Truncate long lines
            if len(lines) > 5:
                print(f"    ... ({len(lines) - 5} more matches)")
        else:
            print("    No matches found.")
    except Exception as e:
        print(f"    Error: {e}")


def find_files(directory, extensions, description):
    print(f"\n[+] Scanning for {description} ({', '.join(extensions)})...")
    found = False
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in extensions):
                print(f"    -> {os.path.join(root, file)}")
                found = True
    if not found:
        print("    None found.")


def unpack_firmware(firmware_path, extract_dir):
    """Unpacks the firmware using containerized tools."""
    print(f"\n[+] Unpacking {firmware_path} using container...")
    
    # Check if podman is available
    if not shutil.which("podman"):
        print("    Error: 'podman' is not installed. Please install it for containerized extraction.")
        return None
    
    abs_firmware_path = os.path.abspath(firmware_path)
    abs_extract_dir = os.path.abspath(extract_dir)
    
    try:
        # Run binwalk in container with volume mounts
        cmd = [
            "podman", "run", "--rm",
            "-v", f"{abs_firmware_path}:/work/firmware.bin:z",
            "-v", f"{abs_extract_dir}:/work/output:z",
            "firmware-extractor",
            "binwalk", "-eM", "/work/firmware.bin", "-C", "/work/output"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"    Binwalk output:\n{result.stdout}")
        
        if result.stderr:
            print(f"    Stderr: {result.stderr}")
        
        # Find the extracted directory (binwalk creates a subdirectory)
        for item in os.listdir(extract_dir):
            item_path = os.path.join(extract_dir, item)
            if os.path.isdir(item_path):
                print(f"    Found extracted directory: {item_path}")
                return item_path
        
        print("    Error: Could not find the extracted directory from binwalk.")
        return None
        
    except Exception as e:
        print(f"    An unexpected error occurred during unpacking: {e}")
        return None


def automate_unpacking(firmware_path, extract_dir):
    """Wrapper function for automated unpacking - used by ingest.py.
    
    Args:
        firmware_path: Path to the firmware file to unpack
        extract_dir: Directory where extracted files will be placed
        
    Returns:
        Path to the extracted directory, or None if unpacking failed
    """
    return unpack_firmware(firmware_path, extract_dir)


def main(target_file):
    if not os.path.exists(target_file):
        print(f"Error: File '{target_file}' does not exist.")
        return

    if not target_file.lower().endswith(".bin"):
        print("Error: This script is intended to be used with .bin files.")
        return

    extract_dir = f"_{os.path.basename(target_file)}"
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir)

    scan_dir = unpack_firmware(target_file, extract_dir)

    if not scan_dir:
        print("\n[!] Halting scan due to unpacking failure.")
        shutil.rmtree(extract_dir)
        return

    print("=" * 60)
    print(f"STARTING CRYPTO SCAN ON: {scan_dir}")
    print("=" * 60)

    # 1. SSL/TLS Libraries (The Engine)
    find_files(
        scan_dir,
        [".so", ".a"],
        "Crypto Libraries (look for libcrypto, libssl, libustream)",
    )

    # 2. Configuration Files (The Rules)
    # Look for ssl_ciphers, PermitRootLogin, etc.
    # We use r"..." for raw strings to handle the grep pipe | safely
    run_grep(
        r"ssl_protocols\|ssl_ciphers\|tls_ciphers\|PermitRootLogin",
        scan_dir,
        "Insecure Configs",
    )

    # 3. Certificates & Keys (The Identity)
    find_files(
        scan_dir,
        [".pem", ".crt", ".key", ".p12", ".der"],
        "Certificates & Private Keys",
    )

    # 4. Web Secrets (The Hardcoded Sins)
    run_grep(
        r"private_key\|secret_key\|auth_token\|api_key",
        scan_dir,
        "Hardcoded Web Secrets",
    )

    # 5. Embedded Keys in Binaries
    run_grep(r"BEGIN RSA PRIVATE KEY", scan_dir, "Embedded RSA Blocks")

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print(f"Extracted files are in: {extract_dir}")
    # Clean up the extracted files
    # shutil.rmtree(extract_dir)
    # print(f"Cleaned up {extract_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 unpack.py <path_to_firmware.bin>")
    else:
        main(sys.argv[1])
