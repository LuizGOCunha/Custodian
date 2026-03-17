import requests

from gather_ips import get_external_ips
from gather_processes import get_processes_by_ip

API_KEY = ""

ips_to_check = get_external_ips()

results = {}
failed_ips = {}
suspicious_ips = []
for ip in ips_to_check:
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {"Key": API_KEY, "Accept": "application/json"}

    params = {"ipAddress": ip, "maxAgeInDays": 90}

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        abuse_score = data["data"]["abuseConfidenceScore"]
        results[ip] = abuse_score
        if int(abuse_score) > 0:
            suspicious_ips.append(ip)

    else:
        results[ip] = f"{response.status_code} - {response.text}"

print("Results:")
for key, value in results.items():
    if key in suspicious_ips:
        print(f"{key} - {value}% - Located in processes: {get_processes_by_ip(key)}")
    else:
        print(f"{key} - {value}%")

print("Failures:")
for key, value in failed_ips.items():
    print(f"{key} - {value}")

pass
