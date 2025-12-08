import json
import sys
import re

def is_primitive_dict(d):
    return isinstance(d, dict) and all(not isinstance(v, (dict, list)) for v in d.values())

def count_dict_blocks(lst):
    return sum(1 for item in lst if isinstance(item, dict))

def extract_keys(obj, indent=0):
    lines = []
    prefix = " " * indent

    if isinstance(obj, dict):
        for key, value in obj.items():

            # --- SPECIAL CASE: edge_level OR node_level OR any *_level ---
            if isinstance(value, list) and isinstance(key, str) and (
                key == "edge_level" or 
                key == "node_level" or 
                re.search(r"_level$", key)
            ):
                count = count_dict_blocks(value)
                lines.append(f"{prefix}{key} - {{ {count} blocks }}")
                continue

            # --- SPECIAL CASE: qiling_dynamic_results ---
            if key == "qiling_dynamic_results" and isinstance(value, dict):
                lines.append(f"{prefix}{key} - {{")
                for subk, subv in value.items():

                    # phases → count blocks
                    if subk == "phases" and isinstance(subv, dict):
                        count = count_dict_blocks(subv.values())
                        lines.append(f"{prefix}    {subk} - {{ {count} blocks }}")
                        continue

                    # verdict → primitive dict summarization
                    if subk == "verdict" and is_primitive_dict(subv):
                        ck = ", ".join(subv.keys())
                        lines.append(f"{prefix}    {subk} - {ck}")
                        continue

                    # raw_output, errors → display name only
                    if isinstance(subv, (str, int, float, bool)):
                        lines.append(f"{prefix}    {subk}")
                        continue

                    # fallback nested dict
                    if isinstance(subv, dict):
                        lines.append(f"{prefix}    {subk} - {{")
                        nested = extract_keys(subv, indent + 8)
                        lines.extend(nested)
                        lines.append(f"{prefix}    }}")
                lines.append(f"{prefix}}}")
                continue

            # --- PRIMITIVE DICT → comma keys ---
            if is_primitive_dict(value):
                ck = ", ".join(value.keys())
                lines.append(f"{prefix}{key} - {ck}")

            # --- Nested dict ---
            elif isinstance(value, dict):
                lines.append(f"{prefix}{key} - {{")
                nested = extract_keys(value, indent + 4)
                lines.extend(nested)
                lines.append(f"{prefix}}}")

            # --- LIST (not edge_level/node_level) ---
            elif isinstance(value, list):
                count = count_dict_blocks(value)
                lines.append(f"{prefix}{key} - {{ {count} blocks }}")

            # --- Ignore primitives ---
            else:
                pass

    return lines


def main():
    if len(sys.argv) < 2:
        print("Usage: python key_extractor.py <input_json>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r") as f:
        data = json.load(f)

    result = extract_keys(data)
    print("\n".join(result))


if __name__ == "__main__":
    main()
