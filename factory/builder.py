import os
import subprocess
import glob

# Configuration
SOURCE_DIR = "source_code"
OUTPUT_DIR = "dataset_binaries"
OS_TYPE = "linux" # Default for this environment

# The Matrix
ARCHITECTURES = {
    "x86": {
        "compilers": ["gcc", "clang"],
        "flags": "-m64",
        "clang_target": ""
    },
    "ARM": {
        "compilers": ["arm-linux-gnueabihf-gcc", "clang"],
        "flags": "-march=armv7-a",
        "clang_target": "--target=arm-linux-gnueabihf"
    },
    "MIPS": {
        "compilers": ["mips-linux-gnu-gcc", "clang"],
        "flags": "-march=mips32",
        "clang_target": "--target=mips-linux-gnu"
    },
    "AVR": {
        "compilers": ["avr-gcc"],
        "flags": "-mmcu=atmega328p",
        "clang_target": "" # Clang AVR support varies
    },
    "RISCV": {
        "compilers": ["riscv64-linux-gnu-gcc", "clang"],
        "flags": "-march=rv64gc -mabi=lp64d",
        "clang_target": "--target=riscv64-linux-gnu"
    },
    "Z80": {
        "compilers": ["sdcc"],
        "flags": "-mz80",
        "clang_target": ""
    }
}

OPTIMIZATIONS = ["-O0", "-O1", "-O2", "-O3", "-Os"]

def compile_binary(source_file, algo_name, arch, compiler, opt):
    base_name = f"{algo_name}_{arch}_{compiler}_{opt.replace('-', '')}"
    
    if arch == "Z80":
        output_file = os.path.join(OUTPUT_DIR, f"{base_name}.ihx")
        sdcc_opt = ""
        if opt == "-O0": sdcc_opt = "--no-peep"
        elif opt == "-Os": sdcc_opt = "--opt-code-size"
        else: sdcc_opt = "--opt-code-speed"
        
        cmd = [compiler, "-mz80", sdcc_opt, source_file, "-o", output_file]
        
    else:
        output_file = os.path.join(OUTPUT_DIR, f"{base_name}.elf")
        flags = ARCHITECTURES[arch]["flags"]
        
        cmd = [compiler]
        
        # Add target if using clang and not x86 (or if target specified)
        if compiler == "clang" and ARCHITECTURES[arch]["clang_target"]:
            cmd.append(ARCHITECTURES[arch]["clang_target"])
            
        cmd += flags.split() + [opt, "-g", source_file, "-o", output_file]

    print(f"Building: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Error building {base_name}: {e.stderr.decode()}")
    except FileNotFoundError:
        print(f"Compiler not found for {base_name}: {cmd[0]}")
    except Exception as e:
        print(f"Unexpected error building {base_name}: {e}")

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    source_files = glob.glob(os.path.join(SOURCE_DIR, "*.c"))
    print(f"Found source files: {source_files}")
    if not source_files:
        print(f"No source files found in {SOURCE_DIR}")
        return

    for source_file in source_files:
        algo_name = os.path.splitext(os.path.basename(source_file))[0]
        print(f"Processing {algo_name}...")
        
        for arch, arch_config in ARCHITECTURES.items():
            print(f"  Architecture: {arch}")
            for compiler in arch_config["compilers"]:
                for opt in OPTIMIZATIONS:
                    # Skip incompatible combinations if any (e.g. clang on MIPS if not installed/configured)
                    compile_binary(source_file, algo_name, arch, compiler, opt)

if __name__ == "__main__":
    main()
