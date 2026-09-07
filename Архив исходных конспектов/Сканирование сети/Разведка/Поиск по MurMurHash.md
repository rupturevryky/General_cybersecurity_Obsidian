```
import pymmh3
import codecs
import sys

def generate_favicon_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            favicon_data = file.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    encoded = codecs.encode(favicon_data, "base64")
    favicon_hash = pymmh3.hash(encoded)
    return favicon_hash

def main():
    
    if len(sys.argv) != 2:
        print("\nUsage: python3 favicon_hash.py <favicon_file>\n")
        sys.exit(1)
    
    file_path = sys.argv[1]
    try:
        result_hash = generate_favicon_hash(file_path)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)
    
    print("\n----------")
    print(result_hash)
    print("----------\n")
    print("Tip: Use http.favicon.hash:<hash> on Shodan to hunt phishing sites.")

if __name__ == "__main__":
    main()
```