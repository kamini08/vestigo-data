import os
import json
import subprocess
import math
import shutil
import pandas as pd
from elftools.elf.elffile import ELFFile
from binary_analysis import BinaryAnalyzer
from predict import predict_from_dataframe

class FirmwareAnalyzer:
    def __init__(self, ghidra_headless_path=None, ghidra_project_dir="./ghidra_projects"):
        self.base_analyzer = BinaryAnalyzer()
        self.ghidra_project_dir = os.path.abspath(ghidra_project_dir)
        if not os.path.exists(self.ghidra_project_dir):
            os.makedirs(self.ghidra_project_dir)
            
        # Auto-detect Ghidra if not provided
        self.ghidra_headless_path = ghidra_headless_path
        if not self.ghidra_headless_path:
            ghidra_home = os.getenv("GHIDRA_HOME")
            if not ghidra_home:
                common_paths = ["/opt/ghidra", "/usr/local/ghidra", os.path.expanduser("~/ghidra")]
                for path in common_paths:
                    if os.path.exists(os.path.join(path, "support", "analyzeHeadless")):
                        ghidra_home = path
                        break
            
            if ghidra_home:
                self.ghidra_headless_path = os.path.join(ghidra_home, "support", "analyzeHeadless")
            else:
                # Fallback to just "analyzeHeadless" in PATH
                self.ghidra_headless_path = "analyzeHeadless"

    def process_binaries(self, binary_list):
        """Iterates through binaries and applies logic loop."""
        results = []
        for binary in binary_list:
            print(f"\n--- Processing: {os.path.basename(binary)} ---")
            
            # Step A: Obfuscation Detection
            is_obfuscated, reason = self.check_obfuscation(binary)
            
            result = {
                "file": binary,
                "status": "Obfuscated" if is_obfuscated else "Not Obfuscated",
                "obfuscation_reason": reason
            }

            # Routing
            if is_obfuscated:
                print(f"[\u26a0\ufe0f] Obfuscation Detected ({reason}). Routing to Dynamic Analysis.")
                dynamic_res = self.run_dynamic_analysis(binary)
                result["action"] = "Routed to Dynamic Analysis"
                result["dynamic_result"] = dynamic_res
            else:
                print(f"[\u2705] Clean Binary. Routing to Static Analysis.")
                static_res = self.run_static_analysis(binary)
                result["action"] = "Routed to Static Analysis"
                result["static_analysis"] = static_res
            
            results.append(result)
        return results

    def check_obfuscation(self, binary_path):
        """Checks for high entropy or packer signatures."""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                
            # 1. Packer Check (UPX)
            if b"UPX!" in content:
                return True, "UPX Packed"
            
            # 2. Entropy Check
            entropy = self.base_analyzer._calculate_shannon_entropy(content)
            if entropy > 7.5:
                return True, f"High Entropy ({entropy:.2f})"
                
        except Exception as e:
            print(f"Error checking obfuscation: {e}")
            
        return False, None

    def run_static_analysis(self, binary_path):
        """Runs Ghidra Headless + ML Inference."""
        
        # 1. Run Ghidra Features Script
        script_path = os.path.abspath("./ghidra_scripts/extract_features.py")
        script_dir = os.path.dirname(script_path)
        script_name = os.path.basename(script_path)
        
        project_name = "temp_project"
        json_output = f"{os.path.basename(binary_path)}_features.json"
        
        # Check if Ghidra is available
        if shutil.which(self.ghidra_headless_path) is None and not os.path.exists(self.ghidra_headless_path):
            print("    [\u26a0\ufe0f] Ghidra Headless not found. Skipping feature extraction.")
            return {"error": "Ghidra not found"}

        # Construct Ghidra Command
        cmd = [
            self.ghidra_headless_path,
            self.ghidra_project_dir,
            project_name,
            "-import", binary_path,
            "-scriptPath", script_dir,
            "-postScript", script_name,
            "-deleteProject" # Clean up after analysis
        ]
        
        print(f"    > Running Ghidra Headless on {os.path.basename(binary_path)}...")
        try:
            # Run Ghidra (suppress stdout to avoid clutter, capture stderr)
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as e:
            print(f"    [!] Ghidra Analysis Failed: {e}")
            return self.base_analyzer.analyze(binary_path)
        except Exception as e:
            print(f"    [!] Error during analysis: {e}")
            return self.base_analyzer.analyze(binary_path)
        
        # 2. Parse JSON Output
        if not os.path.exists(json_output):
            print("    [!] No JSON output found (Extraction failed?).")
            return self.base_analyzer.analyze(binary_path)
            
        with open(json_output, "r") as f:
            data = json.load(f)
            
        # Extract Metadata (Filename/Compiler only now)
        metadata = data.get("metadata", {})
            
        # 3. Convert to DataFrame
        rows = []
        first_arch = "Unknown"
        
        for func in data.get("functions", []):
            # Get arch from function entry
            arch = func.get("arch", "Unknown")
            if first_arch == "Unknown" and arch != "Unknown":
                first_arch = arch
                
            # Flatten structure
            row = {
                "function_name": func["name"],
                "address": func["address"],
                "arch": arch, # Add architecture to features
                # Graph Features
                "cyclomatic_complexity": func["graph_features"]["cyclomatic_complexity"],
                "loop_count": func["graph_features"]["loop_count"],
                "num_basic_blocks": func["graph_features"]["num_blocks"],
                "num_edges": func["graph_features"]["num_edges"],
                # Node Features (List to named columns)
                "bitwise_op_density": func["node_features"][0],
                "n_gram_repetition": func["node_features"][1],
                "carry_chain_depth": func["node_features"][2],
                "immediate_entropy": func["node_features"][3],
                # Constants
                "crypto_constant_hits": len(func["constant_hits"])
            }
            rows.append(row)
            
        print(f"    > Detected Architecture: {first_arch}")
            
        if not rows:
            return {"gnn_classification": "No functions analyzed"}
            
        df = pd.DataFrame(rows)
        
        # 4. Run ML Inference
        print("    > Running ML Inference on extracted features...")
        predictions = predict_from_dataframe(df)
        
        # 5. Aggregate Results
        crypto_funcs = []
        for pred in predictions:
            if pred["predicted_algorithm"] != "Non-Crypto": 
                    crypto_funcs.append(f"{pred['predicted_algorithm']} ({pred['confidence']:.2f})")
        
        # Clean up JSON
        if os.path.exists(json_output):
            os.remove(json_output)
        
        return {
            "gnn_classification": f"Identified {len(crypto_funcs)} crypto functions",
            "details": crypto_funcs,
            "metadata": metadata, # Include full metadata in result
            "raw_predictions": predictions
        }

    # Removed _generate_dummy_features as it is no longer needed

    def run_dynamic_analysis(self, binary_path):
        """Runs QEMU emulation with strace."""
        # 1. Determine Architecture
        arch = self._get_qemu_arch(binary_path)
        if not arch:
            return "Skipped (Unknown Architecture)"
            
        qemu_bin = f"qemu-{arch}-static"
        if shutil.which(qemu_bin) is None:
            return f"Skipped ({qemu_bin} not found)"
            
        print(f"[\u25b6\ufe0f] Running Emulation: {qemu_bin} -strace {binary_path}")
        
        try:
            # Run with timeout
            cmd = [qemu_bin, "-strace", binary_path]
            # We capture stderr because strace output goes there
            result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=5)
            
            output = result.stderr.decode(errors='replace')
            
            # Heuristics
            if "mmap" in output or "mprotect" in output:
                return "Unpacked in memory (mmap/mprotect detected)"
            
            if result.returncode != 0:
                 # Check if it crashed immediately (segfault etc)
                 if "SIGSEGV" in output or "Segmentation fault" in output:
                     return "Emulation Failed (Crash)"
            
            return "Ran successfully (No unpacking detected)"
            
        except subprocess.TimeoutExpired:
            return "Emulation Timeout (Likely running loop)"
        except Exception as e:
            return f"Emulation Error: {e}"

    def _get_qemu_arch(self, binary_path):
        """Maps ELF machine type to QEMU architecture."""
        try:
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                machine = elf.header['e_machine']
                
                # Map common architectures
                if machine == 'EM_ARM':
                    return 'arm'
                elif machine == 'EM_MIPS':
                    return 'mips' # or mipsel depending on endianness
                elif machine == 'EM_X86_64':
                    return 'x86_64'
                elif machine == 'EM_386':
                    return 'i386'
                elif machine == 'EM_AARCH64':
                    return 'aarch64'
                
                # Check endianness for MIPS
                if machine == 'EM_MIPS':
                    return 'mipsel' if elf.little_endian else 'mips'
                    
                return None
        except Exception:
            return None

if __name__ == "__main__":
    # Test
    analyzer = FirmwareAnalyzer()
    # Mock list
    print(json.dumps(analyzer.process_binaries(["/bin/ls"]), indent=2))
