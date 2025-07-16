import requests
import os
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

def get_recent_indicators():
    url = "https://otx.alienvault.com/api/v1/indicators/export"
    params = {"type": "IPv4", "limit": 20}  # You can increase the limit
    response = requests.get(url, headers=HEADERS, params=params)

    if response.status_code == 200:
        data = response.json()
        indicators = []

        for item in data.get("results", data):
            indicators.append({
                "IP": item.get("indicator"),
                "Protocol": extract_protocol(item.get("description")),
                "Port": extract_port(item.get("description")),
                "Created": item.get("created"),
                "Description": item.get("description"),
            })

        df = pd.DataFrame(indicators)
        print(df)
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
def extract_port(description):
    if description and "Port:" in description:
        try:
            return description.split("Port:")[1].split()[0]
        except:
            return None
    return None

def extract_protocol(description):
    if description and "protocol': '" in description:
        try:
            return description.split("protocol': '")[1].split("'")[0]
        except:
            return None
    return None

if __name__ == "__main__":
    get_recent_indicators()

