import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

EVE_LOG_PATH = "/opt/homebrew/var/log/suricata/eve.json"

# Step 1: Pull OTX indicators
def load_otx_indicators():
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        print("OTX API key not found in .env")
        return set()

    headers = {"X-OTX-API-KEY": api_key}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Error {response.status_code}: {response.text}")
        return set()

    indicators = set()
    for pulse in response.json().get("results", []):
        for i in pulse.get("indicators", []):
            indicators.add(i["indicator"])
    return indicators

# Step 2: Parse Suricata logs
def scan_suricata_logs(iocs):
    if not os.path.exists(EVE_LOG_PATH):
        print("Suricata log not found.")
        return

    matches = []

    with open(EVE_LOG_PATH, "r") as log:
        for line in log:
            try:
                event = json.loads(line)
                src = event.get("src_ip")
                dest = event.get("dest_ip")
                if src in iocs or dest in iocs:
                    matches.append({
                        "src_ip": src,
                        "dest_ip": dest,
                        "alert": event.get("alert", {}).get("signature", "No signature")
                    })
            except json.JSONDecodeError:
                continue

    if matches:
        print(f"\n🔍 {len(matches)} matches found:\n")
        for m in matches:
            print(f"- {m['src_ip']} → {m['dest_ip']} | {m['alert']}")
    else:
        print("✅ No matches found.")

if __name__ == "__main__":
    print("🔄 Loading IOCs from OTX...")
    iocs = load_otx_indicators()
    print(f"✅ Loaded {len(iocs)} indicators.")

    print("\n📖 Scanning Suricata logs for matches...")
    scan_suricata_logs(iocs)

