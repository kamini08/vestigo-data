import os
import json
import re
import sys

# Configuration
YARA_FILE = "qiling_analysis/tests/crypto.yar"
JSON_DIR = "filtered_json"
NEGATIVE_DIR = os.path.join(JSON_DIR, "negative")

def parse_yara_rules(yara_path):
    """
    Parses the YARA file to extract algorithm names and byte signatures.
    Returns a list of rules: {'algorithm': 'AES', 'signatures': [[0x63, 0x7C, ...], ...]}
    """
    rules = []
    try:
        with open(yara_path, 'r') as f:
            content = f.read()

        # Remove comments to simplify parsing
        # Remove /* ... */
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Remove // ...
        content = re.sub(r'//.*', '', content)

        # Find start of rules
        # We look for "rule RuleName {"
        # We will iterate through the content and find "rule"
        
        pos = 0
        while True:
            match = re.search(r'\brule\s+(\w+)\s*\{', content[pos:])
            if not match:
                break
            
            rule_name = match.group(1)
            start_brace = pos + match.end() - 1 # Index of '{'
            
            # Find matching closing brace
            brace_count = 1
            i = start_brace + 1
            while i < len(content) and brace_count > 0:
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                i += 1
            
            if brace_count == 0:
                rule_body = content[start_brace+1 : i-1]
                pos = i # Continue from end of this rule
                
                # Extract Algorithm from meta
                algo_match = re.search(r'algorithm\s*=\s*"(.*?)"', rule_body)
                if algo_match:
                    algorithm = algo_match.group(1)
                else:
                    algorithm = rule_name # Fallback

                # Extract byte sequences
                signatures = []
                
                # Find hex strings: $name = { HH HH ... }
                hex_str_pattern = re.compile(r'\$\w+\s*=\s*\{(.*?)\}', re.DOTALL)
                for hex_match in hex_str_pattern.finditer(rule_body):
                    hex_content = hex_match.group(1)
                    # Clean up whitespace (comments already removed)
                    hex_bytes = [int(b, 16) for b in hex_content.split() if re.match(r'^[0-9a-fA-F]{2}$', b)]
                    if hex_bytes:
                        signatures.append(hex_bytes)
                
                # Find text strings: $name = "string"
                text_str_pattern = re.compile(r'\$\w+\s*=\s*"(.*?)"')
                for text_match in text_str_pattern.finditer(rule_body):
                    text_content = text_match.group(1)
                    # Convert string to bytes
                    signatures.append([ord(c) for c in text_content])

                if signatures:
                    rules.append({
                        'name': rule_name,
                        'algorithm': algorithm,
                        'signatures': signatures
                    })
            else:
                # Malformed rule or end of file
                break
                
    except Exception as e:
        print(f"Error parsing YARA file: {e}")
        sys.exit(1)

    return rules

def check_yara_match(immediates, rules):
    """
    Checks if the function's immediates contain any of the YARA signatures.
    Returns the algorithm name if matched, else None.
    """
    if not immediates:
        return None
        
    # Convert immediates to a byte string for easier searching? 
    # Or just sliding window? Immediates is a list of integers.
    # A simple sliding window or string search is safer.
    
    # Optimization: Convert immediates to bytes once
    try:
        # Filter out any values > 255 just in case, though they should be bytes
        imm_bytes = bytes([b for b in immediates if 0 <= b <= 255])
    except Exception:
        return None

    for rule in rules:
        for sig in rule['signatures']:
            sig_bytes = bytes(sig)
            if sig_bytes in imm_bytes:
                return rule['algorithm']
    return None

def infer_algo_from_name(filename, func_name):
    """
    Infers algorithm name from filename or function name.
    """
    # Common crypto names to look for
    # We can use the keys from the original LABEL_MAP or just common strings
    common_algos = {
        "aes": "AES",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha512": "SHA-512",
        "md5": "MD5",
        "des": "DES",
        "chacha": "ChaCha20",
        "salsa": "Salsa20",
        "rc4": "RC4",
        "blowfish": "Blowfish",
        "camellia": "Camellia",
        "rsa": "RSA",
        "ecc": "ECC",
        "hmac": "HMAC",
        "crc32": "CRC32"
    }

    name_lower = func_name.lower()
    file_lower = filename.lower()

    # Check function name first
    for key, val in common_algos.items():
        if key in name_lower:
            return val
            
    # Check filename
    for key, val in common_algos.items():
        if key in file_lower:
            return val
            
    # If filename starts with something that looks like a crypto name
    # e.g. "mycrypto.o" -> "mycrypto"
    # Extract the first part of the filename
    base_name = os.path.basename(filename)
    # Remove extensions and common suffixes
    clean_name = base_name.split('.')[0].split('_')[0]
    
    if len(clean_name) > 2: # Avoid short generic names
        return clean_name.capitalize() # Treat as "Unknown Crypto" with a name

    return None

def fix_json_content(content):
    """
    Attempts to fix common JSON errors:
    - Trailing commas before closing brackets/braces
    - Truncated/incomplete JSON structures
    """
    import re
    
    lines = content.split('\n')
    
    # First pass: remove trailing commas before closing brackets
    fixed_lines = []
    for i, line in enumerate(lines):
        stripped = line.rstrip()
        
        if stripped.endswith(','):
            # Look ahead to see if the next non-empty content is a closing bracket
            next_content = None
            for j in range(i + 1, len(lines)):
                next_stripped = lines[j].strip()
                if next_stripped:
                    next_content = next_stripped
                    break
            
            # If next content starts with closing bracket or we're at end, remove the trailing comma
            if (next_content and (next_content.startswith(']') or next_content.startswith('}'))) or j >= len(lines):
                line = stripped[:-1] + line[len(stripped):]
        
        fixed_lines.append(line)
    
    content = '\n'.join(fixed_lines)
    
    # Second pass: Handle truncated JSON by tracking bracket depth
    try:
        json.loads(content)
        return content  # Already valid
    except json.JSONDecodeError as e:
        # Remove trailing empty lines
        content = content.rstrip()
        
        # Track nesting using a stack-based approach
        stack = []
        in_string = False
        escape_next = False
        
        for char in content:
            if escape_next:
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                continue
            
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            
            if not in_string:
                if char in '{[':
                    stack.append(char)
                elif char in '}]':
                    if stack and ((char == '}' and stack[-1] == '{') or (char == ']' and stack[-1] == '[')):
                        stack.pop()
        
        # Remove trailing comma if present
        if content.rstrip().endswith(','):
            content = content.rstrip()[:-1]
        
        # Close any unclosed structures
        content += '\n'
        while stack:
            opener = stack.pop()
            if opener == '{':
                content += '    }\n'
            elif opener == '[':
                content += '    ]\n'
        
        return content

def load_json_with_repair(file_path):
    """
    Attempts to load JSON, with automatic repair if initial load fails.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            return json.loads(content)
    except json.JSONDecodeError as e:
        # Try to repair the JSON
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Additional preprocessing for common issues
            # Remove any invalid control characters
            content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
            
            fixed_content = fix_json_content(content)
            data = json.loads(fixed_content)
            
            # Write back the fixed version
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            
            print(f"  Repaired and reloaded: {os.path.basename(file_path)}")
            return data
        except json.JSONDecodeError as je:
            # If it's still a structural issue, try more aggressive fixes
            try:
                # Try to find where the JSON becomes invalid and truncate before that point
                lines = content.split('\n')
                # Find the last valid closing brace/bracket combination
                for cutoff in range(len(lines) - 1, max(0, len(lines) - 100), -1):
                    test_content = '\n'.join(lines[:cutoff])
                    test_fixed = fix_json_content(test_content)
                    try:
                        data = json.loads(test_fixed)
                        print(f"  Repaired by truncating at line {cutoff}: {os.path.basename(file_path)}")
                        with open(file_path, 'w') as f:
                            json.dump(data, f, indent=4)
                        return data
                    except:
                        continue
                raise Exception(f"Failed to repair JSON: {je}")
            except Exception as repair_error:
                raise Exception(f"Failed to repair JSON: {repair_error}")

def process_files():
    import argparse
    parser = argparse.ArgumentParser(description="Label functions in JSON files using YARA rules.")
    parser.add_argument("directory", nargs="?", default="filtered_json", help="Directory containing JSON files to process")
    args = parser.parse_args()
    
    target_dir = args.directory
    
    print(f"Parsing YARA rules from {YARA_FILE}...")
    yara_rules = parse_yara_rules(YARA_FILE)
    print(f"Loaded {len(yara_rules)} rules.")

    if not os.path.exists(target_dir):
        print(f"Directory {target_dir} not found.")
        return

    count = 0
    error_count = 0
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if not file.endswith(".json"):
                continue
                
            file_path = os.path.join(root, file)
            # Check if file is in a 'negative' subdirectory relative to the target_dir or absolute path
            is_negative = "/negative/" in file_path or os.path.sep + "negative" + os.path.sep in file_path
            
            try:
                data = load_json_with_repair(file_path)
                
                updated = False
                if "functions" in data:
                    for func in data["functions"]:
                        original_label = func.get("label", "Unknown")
                        new_label = "Unknown"
                        
                        if is_negative:
                            new_label = "non-crypto"
                        else:
                            # 1. YARA Match
                            immediates = func.get("node_level", [])
                            # Flatten immediates from all nodes
                            all_immediates = []
                            for node in func.get("node_level", []):
                                all_immediates.extend(node.get("immediates", []))
                            
                            yara_label = check_yara_match(all_immediates, yara_rules)
                            
                            if yara_label:
                                new_label = yara_label
                            else:
                                # 2. Name / Filename Inference
                                func_name = func.get("name", "")
                                inferred = infer_algo_from_name(file, func_name)
                                if inferred:
                                    new_label = inferred
                                else:
                                    # 3. Default for positive samples that don't match
                                    new_label = "non-crypto"

                        if new_label != original_label:
                            func["label"] = new_label
                            updated = True
                
                if updated:
                    with open(file_path, 'w') as f:
                        json.dump(data, f, indent=4)
                    # print(f"Updated {file}")
                    count += 1
                    
            except Exception as e:
                print(f"Error processing {file}: {e}")
                error_count += 1

    print(f"Finished processing. Updated {count} files in {target_dir}.")
    if error_count > 0:
        print(f"Encountered {error_count} errors during processing.")

if __name__ == "__main__":
    process_files()