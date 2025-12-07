import json
import sys

def extract_keys(obj, indent=0):
    """Format JSON keys using commas and nested { } blocks."""
    lines = []
    prefix = " " * indent

    if isinstance(obj, dict):
        for key, value in obj.items():

            # SPECIAL CASE: edge_level → count blocks only
            if key == "edge_level" and isinstance(value, list):
                count = sum(1 for item in value if isinstance(item, dict))
                lines.append(f"{prefix}{key} - {{ {count} blocks }}")
                continue

            # Case 1: dict but children all primitives → comma list
            if isinstance(value, dict) and all(not isinstance(v, (dict, list)) for v in value.values()):
                child_keys = ", ".join(value.keys())
                lines.append(f"{prefix}{key} - {child_keys}")

            # Case 2: nested dict → block
            elif isinstance(value, dict):
                lines.append(f"{prefix}{key} - {{")
                nested = extract_keys(value, indent + 4)
                lines.extend(nested)
                lines.append(f"{prefix}}}")

            # Case 3: list of dicts → nested block
            elif isinstance(value, list):
                # edge_level handled above
                lines.append(f"{prefix}{key} - {{")
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        lines.append(f"{prefix}    [{i}] - {{")
                        nested = extract_keys(item, indent + 8)
                        lines.extend(nested)
                        lines.append(f"{prefix}    }}")
                lines.append(f"{prefix}}}")

            # Case 4: primitive → skip
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
    