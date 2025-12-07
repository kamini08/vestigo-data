import os
import json
import shutil

INPUT_DIR = "ghidra_json_new"
OUTPUT_DIR = "filtered_json"

def main():
    # Create output folder if not exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    files = os.listdir(INPUT_DIR)
    json_files = [f for f in files if f.endswith(".json")]

    kept = 0
    ignored = 0

    for filename in json_files:
        path = os.path.join(INPUT_DIR, filename)

        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Skipping invalid JSON: {filename}, error: {e}")
            ignored += 1
            continue

        # Check condition: num_functions > 0
        num_funcs = data.get("metadata", {}).get("num_functions", 1)

        if num_funcs > 0:
            # Copy this JSON to the output folder
            shutil.copy(path, os.path.join(OUTPUT_DIR, filename))
            kept += 1
        else:
            ignored += 1

    print(f"➤ JSON files kept: {kept}")
    print(f"➤ JSON files ignored (no functions): {ignored}")
    print(f"➤ Output saved in: {OUTPUT_DIR}/")

if __name__ == "__main__":
    main()
