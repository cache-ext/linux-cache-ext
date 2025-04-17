import sys

def count_loc(filename):
    loc = 0
    in_multiline_comment = False

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Handle multi-line comments
            if "/*" in line:
                in_multiline_comment = True
                if "*/" in line:
                    in_multiline_comment = False
                continue

            if "*/" in line:
                in_multiline_comment = False
                continue

            if in_multiline_comment:
                continue

            # Skip single line comments
            if line.startswith("//"):
                continue

            # Count non-comment, non-empty lines
            loc += 1

    return loc

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python loc_count.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    loc = count_loc(filename)
    print(f"Lines of code (excluding comments and empty lines): {loc}")
