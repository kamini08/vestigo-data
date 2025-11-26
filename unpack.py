import os
import subprocess
import sys


def run_command(command):
    """Helper to run shell commands."""
    try:
        subprocess.run(command, check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {' '.join(command)}")


def convert_to_binary(file_path, ext):
    """Automates Step 2C: Converts .hex or .srec to .bin"""
    base_name = os.path.splitext(file_path)[0]
    output_bin = f"{base_name}.bin"

    # Determine format flag based on extension
    input_format = "ihex" if ext == "hex" else "srec"

    print(f"Pre-processing: Converting {ext.upper()} to raw BINARY...")
    cmd = ["objcopy", "-I", input_format, "-O", "binary", file_path, output_bin]
    run_command(cmd)

    if os.path.exists(output_bin):
        return output_bin
    return None


def automate_unpacking(file_path):
    """The Main Logic"""
    if not os.path.exists(file_path):
        print("File not found.")
        return

    filename = os.path.basename(file_path)
    ext = filename.split(".")[-1].lower()
    target_file = file_path

    print(f"\n--- Analyzing: {filename} ---")

    # If text-based firmware, convert it first
    if ext in ["hex", "srec"]:
        new_bin = convert_to_binary(file_path, ext)
        if new_bin:
            target_file = new_bin
            print(f"Conversion successful. New target: {target_file}")
        else:
            print("Conversion failed. Skipping.")
            return

    # If ELF, just tell user what tools to use
    if ext == "elf":
        print("ELF detected. Use Ghidra or Readelf on this file.")
        return

    print(f"Running Binwalk (Recursive Extraction)...")
    # -e: Extract, -M: Matryoshka (Recursive), -q: Quiet mode
    cmd = ["binwalk", "-eM", "-q", target_file]
    run_command(cmd)
    print("Extraction Attempt Complete.\n")


# You can pass a single file or a directory loop here
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 unpacker.py <firmware_file>")
    else:
        automate_unpacking(sys.argv[1])
