import os
import sys
import requests

def check_ip(ip_address):
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("ERROR: ABUSEIPDB_API_KEY environment variable is not set.")
        sys.exit(1)

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"ERROR: API request failed with status {response.status_code}")
        print(response.text)
        sys.exit(1)

    data = response.json()["data"]
    print(f"\nIP: {data['ipAddress']}")
    print(f"Abuse Confidence Score: {data['abuseConfidenceScore']}%")
    print(f"Country: {data.get('countryCode', 'Unknown')}")
    print(f"ISP: {data.get('isp', 'Unknown')}")
    print(f"Total Reports: {data['totalReports']}")
    print(f"Is Whitelisted: {data.get('isWhitelisted', False)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_ip.py <ip_address>")
        sys.exit(1)

    check_ip(sys.argv[1])
