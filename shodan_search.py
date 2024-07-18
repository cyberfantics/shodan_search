# -*- coding: utf-8 -*-
"""
Created on Thu Jul 18 11:29:16 2024

@author: Mansoor
"""

import shodan
import time
import json

# Read Shodan API key from file
with open("shodan_api.txt", "r") as f:
    key = f.read().strip()
api = shodan.Shodan(key)

def queryShodan(query):
    hosts = {}
    try:
        results = api.search(query)
        for service in results["matches"]:
            ip = service["ip_str"]
            port_info = {
                "port": service["port"],
                "service": service["product"] if "product" in service else None,
                "version": service["version"] if "version" in service else None,
                "cpe": service["cpe"] if "cpe" in service else None,
                "banner": service["data"]
            }
            geolocation = {
                "country": service["location"]["country_name"],
                "city": service["location"]["city"],
                "latitude": service["location"]["latitude"],
                "longitude": service["location"]["longitude"]
            }
            organization = service["org"]
            vulnerabilities = service.get("vulns", [])

            if ip in hosts:
                hosts[ip]["ports"].append(port_info)
            else:
                hosts[ip] = {
                    "ports": [port_info],
                    "geolocation": geolocation,
                    "organization": organization,
                    "vulnerabilities": vulnerabilities
                }
        return hosts
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        if "rate limit" in str(e).lower():
            print("Rate limit exceeded. Waiting for 60 seconds...")
            time.sleep(60)
        return {}
    except Exception as e:
        print(f"Error: {e}")
        return {}

def ShodanLookup(ip):
    try:
        results = api.host(ip)
        records = []
        for item in results["data"]:
            r = {
                "port": item["port"],
                "banner": item["data"],
                "geolocation": {
                    "country": results["country_name"],
                    "city": results["city"],
                    "latitude": results["latitude"],
                    "longitude": results["longitude"]
                },
                "organization": results["org"],
                "vulnerabilities": item.get("vulns", []),
                "service": item["product"] if "product" in item else None,
                "version": item["version"] if "version" in item else None,
                "cpe": item["cpe"] if "cpe" in item else None
            }
            records.append(r)
        return records
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        if "rate limit" in str(e).lower():
            print("Rate limit exceeded. Waiting for 60 seconds...")
            time.sleep(60)
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def saveResultsToFile(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results to file: {e}")

def generateSummary(data):
    summary = {
        "total_unique_ips": len(data),
        "total_ports": sum(len(host["ports"]) for host in data.values()),
        "total_vulnerabilities": sum(len(host["vulnerabilities"]) for host in data.values())
    }
    return summary

def formatDataForSaving(data, summary):
    formatted_data = {
        "summary": summary,
        "hosts": data
    }
    return formatted_data

# Example Use Of IT
query = "apache"
hosts = queryShodan(query)
summary = generateSummary(hosts)
formatted_data = formatDataForSaving(hosts, summary)
saveResultsToFile("shodan_results.json", formatted_data)

ip = "8.8.8.8"
lookup_results = ShodanLookup(ip)
saveResultsToFile(f"{ip}_lookup.json", lookup_results)
