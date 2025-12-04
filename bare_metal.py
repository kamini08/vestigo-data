import os
import subprocess
import json
import shutil
import time
import sys

class BareMetalAnalyzer:
    def __init__(self):
        self.ghidra_home = os.getenv("GHIDRA_HOME")
        self.project_dir = "/tmp/ghidra_temp_project"
        self.script_path = "ghidra_scripts/extract_features.py"
        self.ml_script_path = "ml/enhanced_predict_crypto.py"
        self.output_dir = "ghidra_json"
        
        # Auto-detect Ghidra if not set
        if not self.ghidra_home:
            common_paths = ["/opt/ghidra", "/usr/local/ghidra", os.path.expanduser("~/ghidra")]
            for path in common_paths:
                if os.path.exists(os.path.join(path, "support", "analyzeHeadless")):
                    self.ghidra_home = path
                    break
    
    def _run_ghidra(self, binary_path):
        """Runs Ghidra headless analysis on the binary"""
        if not self.ghidra_home:
            print("    [!] Error: GHIDRA_HOME not set and not found.")
            return None

        print(f"    > Running Ghidra analysis on {os.path.basename(binary_path)}...")
        
        analyzer_bin = os.path.join(self.ghidra_home, "support", "analyzeHeadless")
        project_name = f"temp_analysis_{int(time.time())}"
        
        # Ensure clean state
        if os.path.exists(self.project_dir):
            shutil.rmtree(self.project_dir)
        os.makedirs(self.project_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        
        cmd = [
            analyzer_bin,
            self.project_dir,
            project_name,
            "-import", binary_path,
            "-postScript", os.path.abspath(self.script_path),
            "-deleteProject"
        ]
        
        try:
            # Run Ghidra (suppress output unless error)
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            
            # Check for output
            binary_name = os.path.basename(binary_path)
            expected_json = os.path.join(self.output_dir, f"{binary_name}_features.json")
            
            if os.path.exists(expected_json):
                print("    > Ghidra analysis complete.")
                return expected_json
            else:
                print("    [!] Ghidra finished but no output JSON found.")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"    [!] Ghidra analysis failed: {e.stderr.decode()}")
            return None
        except Exception as e:
            print(f"    [!] Error running Ghidra: {e}")
            return None

    def _run_ml_model(self, features_path):
        """Runs the ML prediction script on the extracted features"""
        print("    > Running ML Crypto Prediction...")
        
        cmd = [
            sys.executable,
            self.ml_script_path,
            "--features", features_path
        ]
        
        try:
            # Run ML script and capture output
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"    [!] ML prediction failed: {result.stderr}")
                return None
            
            # Parse the output to extract the JSON part or structured data
            # The script prints a report, but we might want to modify it to output JSON
            # For now, we'll return the raw output as the report
            return result.stdout
            
        except Exception as e:
            print(f"    [!] Error running ML model: {e}")
            return None

    def analyze(self, binary_path):
        """Main analysis flow"""
        report = {
            "module": "Bare_Metal_ML",
            "ghidra_features": None,
            "ml_prediction": None,
            "error": None
        }
        
        # 1. Run Ghidra
        features_json_path = self._run_ghidra(binary_path)
        
        if features_json_path:
            # Load features into report
            try:
                with open(features_json_path, 'r') as f:
                    report["ghidra_features"] = json.load(f)
            except:
                report["ghidra_features"] = "Error reading JSON"
            
            # 2. Run ML Model
            ml_output = self._run_ml_model(features_json_path)
            report["ml_prediction"] = ml_output
        else:
            report["error"] = "Ghidra analysis failed"
            
        return report
