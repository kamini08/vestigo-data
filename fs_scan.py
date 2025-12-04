import os
import subprocess
import re
import json
import stat

class AdvancedLinuxAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.remediation_script = []
        
        # Regex for high-entropy/secret strings (AWS keys, Private Keys, etc.)
        self.SECRET_PATTERNS = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "Generic API Token": r"(api_key|auth_token|client_secret)\s*[:=]\s*['\"][a-zA-Z0-9]{32,}['\"]"
        }

    def _run(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
        except:
            return ""

    # --- FEATURE 1: BINARY HARDENING (Exploit Mitigation) ---
    def check_binary_protection(self, file_path):
        """Checks ELF binaries for security flags (NX, PIE, RELRO, Canary)"""
        # We use readelf to check header flags
        output = self._run(f"readelf -lW '{file_path}' 2>/dev/null")
        sec_output = self._run(f"readelf -s '{file_path}' 2>/dev/null")
        
        protection = {
            "NX": False,      # Non-Executable Stack
            "PIE": False,     # Position Independent Executable
            "Canary": False,  # Stack Smashing Protection
            "RELRO": "No"     # Read-Only Relocations
        }

        # Check NX (GNU_STACK segment should essentially NOT have 'E' executable flag)
        if "GNU_STACK" in output and "RWE" not in output: 
            protection["NX"] = True
            
        # Check PIE (Type should be DYN, not EXEC)
        header = self._run(f"readelf -h '{file_path}'")
        if "Type:" in header and "DYN" in header:
            protection["PIE"] = True

        # Check Canary (Look for __stack_chk_fail symbol)
        if "__stack_chk_fail" in sec_output:
            protection["Canary"] = True

        # Check RELRO
        if "GNU_RELRO" in output:
            if "BIND_NOW" in self._run(f"readelf -d '{file_path}'"):
                protection["RELRO"] = "Full"
            else:
                protection["RELRO"] = "Partial"

        return protection

    # --- FEATURE 2: SHADOW FILE AUDIT (Weak Hashing) ---
    def audit_shadow(self, fs_path):
        shadow_path = os.path.join(fs_path, "etc/shadow")
        if not os.path.exists(shadow_path): return

        print("    > Auditing /etc/shadow for weak hashes...")
        try:
            with open(shadow_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) < 2: continue
                    
                    user = parts[0]
                    hash_str = parts[1]
                    
                    # Analyze Hash Type
                    algo = "Unknown"
                    if hash_str.startswith("$1$"): algo = "MD5 (WEAK)"
                    elif hash_str.startswith("$5$"): algo = "SHA-256 (OK)"
                    elif hash_str.startswith("$6$"): algo = "SHA-512 (GOOD)"
                    elif hash_str.startswith("$y$"): algo = "Yescrypt (STRONG)"
                    elif len(hash_str) == 13: algo = "DES (CRITICAL)"
                    
                    if "WEAK" in algo or "CRITICAL" in algo:
                        self.vulnerabilities.append(f"User '{user}' uses weak hashing: {algo}")
                        # Add fix to remediation script
                        self.remediation_script.append(f"# Fix weak password for {user}")
                        self.remediation_script.append(f"passwd -l {user} # Locking account recommended until fixed")
        except Exception as e:
            print(f"Error reading shadow: {e}")

    # --- FEATURE 3: RECURSIVE SECRET SCANNING ---
    def scan_secrets(self, fs_path):
        print("    > Deep scanning for embedded secrets...")
        hits = []
        # Limit depth and file size to prevent hanging
        for root, _, files in os.walk(fs_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                # Skip binaries for regex scan (too slow/noisy), handled by strings check elsewhere
                if not fname.endswith(('.conf', '.sh', '.py', '.txt', '.xml', '.json', '.pem', '.key')):
                    continue
                
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                        for name, pattern in self.SECRET_PATTERNS.items():
                            if re.search(pattern, content):
                                rel_path = fpath.replace(fs_path, "")
                                hits.append({"file": rel_path, "type": name})
                                self.vulnerabilities.append(f"Hardcoded {name} found in {rel_path}")
                                # Suggest deletion
                                self.remediation_script.append(f"rm '.{rel_path}' # Potential secret leak")
                except: pass
        return hits

    # --- FEATURE 4: CONFIG AUTO-FIXER ---
    def analyze_and_fix_configs(self, fs_path):
        print("    > Analyzing configs and generating patches...")
        
        # SSH Config
        sshd_config = os.path.join(fs_path, "etc/ssh/sshd_config")
        if os.path.exists(sshd_config):
            with open(sshd_config, 'r') as f:
                content = f.read()
                
            if "PermitRootLogin yes" in content:
                self.vulnerabilities.append("SSH Root Login Allowed")
                self.remediation_script.append(f"sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config")
            
            if "Protocol 1" in content:
                self.vulnerabilities.append("SSH Protocol 1 Enabled (Obsolete)")
                self.remediation_script.append(f"sed -i 's/Protocol 1/Protocol 2/g' /etc/ssh/sshd_config")

    # --- MAIN ANALYZER ---
    def analyze(self, fs_path):
        print(f"[*] Advanced Module 2: Deep Scan on {fs_path}")
        
        report = {
            "binary_hardening": {},
            "secrets": [],
            "vulnerabilities": [],
            "generated_fix_script": ""
        }

        # 1. Binary Hardening Scan
        bin_path = os.path.join(fs_path, "bin")
        if os.path.exists(bin_path):
            print("    > Checking Binary Hardening (NX/PIE/Canary)...")
            for f in os.listdir(bin_path):
                full_p = os.path.join(bin_path, f)
                # Check if executable
                if os.path.isfile(full_p) and os.access(full_p, os.X_OK):
                    # Skip symlinks
                    if not os.path.islink(full_p):
                        report["binary_hardening"][f] = self.check_binary_protection(full_p)

        # 2. Run Sub-Scans
        report["secrets"] = self.scan_secrets(fs_path)
        self.audit_shadow(fs_path)
        self.analyze_and_fix_configs(fs_path)

        # 3. Finalize Report
        report["vulnerabilities"] = self.vulnerabilities
        
        # 4. Generate the Fix Script
        fix_content = "#!/bin/bash\n# Auto-Generated Hardening Script by Vestigo\n\n"
        fix_content += "\n".join(self.remediation_script)
        report["generated_fix_script"] = fix_content
        
        # Save the script to disk
        with open("hardening_patch.sh", "w") as f:
            f.write(fix_content)
        
        print(f"[\u2713] Deep Scan Complete. Generated 'hardening_patch.sh'.")
        return report

if __name__ == "__main__":
    # Test run
    analyzer = AdvancedLinuxAnalyzer()
    # Create dummy shadow for test
    os.makedirs("test_fs/etc/ssh", exist_ok=True)
    with open("test_fs/etc/shadow", "w") as f: f.write("root:$1$salt$hash:0:0:99999:7:::\n") # MD5 weak
    with open("test_fs/etc/ssh/sshd_config", "w") as f: f.write("PermitRootLogin yes\n")
    
    print(json.dumps(analyzer.analyze("test_fs"), indent=4))
    
    # Clean up
    import shutil
    if os.path.exists("test_fs"):
        shutil.rmtree("test_fs")
