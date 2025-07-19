import json
import argparse
import requests
import sys
import os

# ====== CONFIG ======
CONFIG = {
    "LOG_PATH": "/opt/homebrew/var/log/suricata/eve.json",
    "OUTPUT_FILE": "matched_iocs.json",
    "OTX_API_KEY": "9155ab7ceda7bf9179f7750c290f6315581b95d29eef43834ae47a0f53e57abc",
    "PULSE_COUNT": 5
}

# ====== FUNCTIONS ======

def load_suricata_logs(path, debug=False):
    try:
        print("🔄 Loading Suricata logs...")
        with open(path, "r") as f:
            data = [json.loads(line) for line in f if line.strip()]
        print(f"✅ Loaded {len(data)} log entries.")
        return data
    except FileNotFoundError:
        print(f"❌ E201: Suricata log file not found at '{path}'")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ E202: Failed to parse JSON log file: {e}")
        if debug:
            raise
        sys.exit(1)


def fetch_otx_iocs(api_key, pulse_count=5, debug=False):
    headers = {'X-OTX-API-KEY': api_key}
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={pulse_count}"

    try:
        print("🌐 Fetching IOCs from OTX...")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        indicators = [i["indicator"] for pulse in data["results"] for i in pulse["indicators"]]
        print(f"✅ Retrieved {len(indicators)} IOCs.")
        return set(indicators)
    except requests.exceptions.RequestException as e:
        print(f"❌ E101: Failed to fetch from OTX API: {e}")
        if debug:
            raise
        sys.exit(1)


def correlate_iocs(logs, iocs, debug=False):
    print("🔍 Correlating IOCs with Suricata logs...")
    matches = []

    for entry in logs:
        try:
            alert = entry.get("alert", {})
            src = entry.get("src_ip")
            dest = entry.get("dest_ip")

            if src in iocs or dest in iocs:
                match = {
                    "timestamp": entry.get("timestamp"),
                    "src_ip": src,
                    "dest_ip": dest,
                    "alert_signature": alert.get("signature", "N/A")
                }
                matches.append(match)

                if debug:
                    print(f"🧨 Match found: {match}")
        except Exception as e:
            if debug:
                print(f"⚠️ Error processing entry: {e}")
                raise

    print(f"✅ Correlation complete: {len(matches)} matches found.")
    return matches


def write_output(matches, path):
    try:
        with open(path, "w") as f:
            json.dump(matches, f, indent=4)
        print(f"📁 Results written to {path}")
    except Exception as e:
        print(f"❌ E401: Failed to write output: {e}")
        sys.exit(1)


def run_pipeline(log_path, api_key, output_file, pulse_count, debug=False):
    logs = load_suricata_logs(log_path, debug)
    iocs = fetch_otx_iocs(api_key, pulse_count, debug)
    matches = correlate_iocs(logs, iocs, debug)
    write_output(matches, output_file)

    # New notification logic
    if matches:
        print("\n🚨 Suspicious activity detected!")
        print(f"🧨 Total matched events: {len(matches)}")
        print("📁 Details saved to:", output_file)
    else:
        print("\n✅ No suspicious activity matched the current IOCs.")


def run_test(debug=False):
    print("🧪 Running test pipeline with mock data...")
    mock_logs = [
        {"timestamp": "2025-01-01T00:00:00Z", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {"signature": "Test Sig"}},
        {"timestamp": "2025-01-01T01:00:00Z", "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "alert": {"signature": "DNS Leak"}}
    ]
    mock_iocs = {"1.2.3.4", "8.8.8.8"}
    matches = correlate_iocs(mock_logs, mock_iocs, debug)
    write_output(matches, "test_output.json")


# ====== MAIN ======

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intel Correlation Script")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--test", action="store_true", help="Run with mock data only")
    args = parser.parse_args()

    if args.test:
        run_test(debug=args.debug)
    else:
        run_pipeline(
            CONFIG["LOG_PATH"],
            CONFIG["OTX_API_KEY"],
            CONFIG["OUTPUT_FILE"],
            CONFIG["PULSE_COUNT"],
            debug=args.debug
        )

