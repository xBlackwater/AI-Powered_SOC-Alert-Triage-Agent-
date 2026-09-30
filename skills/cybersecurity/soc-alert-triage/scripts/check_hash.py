import os
import sys
import requests

def check_hash(file_hash):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("ERROR: VT_API_KEY environment variable is not set.")
        sys.exit(1)

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        print(f"\nHash {file_hash} was NOT found in VirusTotal's database.")
        print("This could mean it's new/unseen, or it's not actually malicious.")
        return

    if response.status_code != 200:
        print(f"ERROR: API request failed with status {response.status_code}")
        print(response.text)
        sys.exit(1)

    data = response.json()["data"]["attributes"]
    stats = data["last_analysis_stats"]

    print(f"\nHash: {file_hash}")
    print(f"File type: {data.get('type_description', 'Unknown')}")
    print(f"File name(s): {', '.join(data.get('names', ['Unknown'])[:3])}")
    print(f"\nDetection results:")
    print(f"  Malicious:  {stats['malicious']}")
    print(f"  Suspicious: {stats['suspicious']}")
    print(f"  Undetected: {stats['undetected']}")
    print(f"  Harmless:   {stats['harmless']}")
    total = sum(stats.values())
    print(f"\nFlagged by {stats['malicious']}/{total} security vendors")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_hash.py <file_hash>")
        sys.exit(1)

    check_hash(sys.argv[1])
