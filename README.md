# Shodan Search Tool

This Python script utilizes the Shodan API to search for and retrieve information about hosts on the internet. The script provides detailed information about the ports, services, geolocation, organization, and vulnerabilities associated with each host. It also includes functionalities to save the results in a formatted JSON file.

## Features

- Search Shodan using a query
- Retrieve detailed information about specific IP addresses
- Include geolocation and organization information
- List known vulnerabilities associated with the hosts
- Save results to a JSON file in a readable format
- Generate a summary of the results

## Requirements

- Python 3.x
- `shodan` module (`pip install shodan`)

## Usage

1. **Setup Shodan API Key:**
   - Place your Shodan API key in a file named `shodan_api.txt`.

2. **Run the Script:**
   - Clone the repository by running `git clone https://github.com/cyberfantics/shodan_search.git`
   - Change Diroctory by running `cd shodan_search`
   - Execute the script by running `python shodan_search.py` in your terminal.

4. **Example Query and IP Lookup:**
   - The script includes an example query (`"apache"`) and an example IP lookup (`"8.8.8.8"`).

## Functions

- `queryShodan(query)`: Searches Shodan using the provided query and returns detailed information about the hosts.
- `ShodanLookup(ip)`: Retrieves detailed information about a specific IP address.
- `saveResultsToFile(filename, data)`: Saves the results to a JSON file.
- `generateSummary(data)`: Generates a summary of the results, including the total number of unique IPs, total ports, and total vulnerabilities.
- `formatDataForSaving(data, summary)`: Formats the data and summary for saving to a file.

## Developer
Syed Mansoor ul Hassan Bukhari [GitHub](https:github.com/cyberfantics)
