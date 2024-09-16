import configparser
import requests
import sys
import shodan
import pandas as pd
import re
from colorama import Fore, Style

# API Keys from config.cfg
def cargar_claves_api(file):
    config = configparser.ConfigParser()
    config.read(file)
    claves = {}
    claves['shodan_api_key'] = config.get('API Keys', 'SHODAN_API_KEY')
    claves['binaryedge_api_key'] = config.get('API Keys', 'BINARYEDGE_API_KEY')
    claves['fofa_api_email'] = config.get('API Keys', 'FOFA_API_EMAIL')
    claves['fofa_api_key'] = config.get('API Keys', 'FOFA_API_KEY')
    return claves

#Shodan
def consultar_shodan(api_key, etag):
    api = shodan.Shodan(api_key)
    try:
        results = api.search(etag)
        if results['total'] > 0:
            data = []
            for match in results['matches']:
                info = {
                    'IP': match['ip_str'],
                    'País': match['location']['country_name'],
                    'ISP': match['isp'],
                    # You can add more fields here
                }
                data.append(info)
            
            df = pd.DataFrame(data)
            return df
        else:
            return None
    except shodan.APIError as e:
        print('Shodan Request Error:', e)

# BinaryEdge
def consultar_binaryedge(api_key, etag):
    # BinaryEdge API URL
    url = f"https://api.binaryedge.io/v2/query/search"

    # request parameters
    params = {
        "query": f"etag:{etag}"
    }
    headers = {
        "X-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, params=params, headers=headers)

        # Verify the response status code
        if response.status_code == 200:
            data = response.json()
            if "events" in data:
                results = data["events"]
                if len(results) > 0:
                    result_table = pd.DataFrame(columns=["IP", "Country"])
                    for result in results:
                        ip = result["target"]["ip"]
                        country = result["origin"]["country"]
                        result_table = pd.concat([result_table, pd.DataFrame({"IP": [ip], "Country": [country]})], ignore_index=True)
                    return result_table
                else:
                    return None
            else:
                print("The BinaryEdge Response does not contain data.")
                return None
        else:
            print("BinaryEdge query error:", response.text)
            return None
    except requests.exceptions.RequestException as e:
        print("Connection errror:", e)

# FOFA
def consultar_fofa(email, key, query):
    url = "https://fofa.info/api/v1/search/all"
    headers = {
        "X-Email": email,
        "X-Key": key
    }
    params = {
        "qbase64": query,
        "full": "true"
    }
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if 'results' in data:
            if len(data['results']) > 0:
                return data['results'][0]
    return None

def process_url(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        claves = cargar_claves_api('your_api_keys.cfg')
        shodan_api_key = claves['shodan_api_key']
        binaryedge_api_key = claves['binaryedge_api_key']
        fofa_api_email = claves['fofa_api_email']
        fofa_api_key = claves['fofa_api_key']

        # Request over Tor (You have to have the Tor service running)
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050'
        }
        response = session.get(url, stream=True, timeout=30)

        if response.status_code == 200:

            etag = response.headers.get('ETag')
            
            #etag para pruebas
            #etag = "5d255abe-4b0"   
            #etag = 'W/"91-1319045231000"'

            success_icon = "✔"
            failure_icon = "✗"
                
            success_color = "\033[92m"  # Green for success
            failure_color = "\033[91m"  # Red for failure
            reset_color = "\033[0m"  # Reset to default color

            if etag:
                pattern = r'"([^"]*)"' # Regex pattern to extract the ETag value
                matches = re.findall(pattern, etag)

                if len(matches) > 0:
                    etag = matches[0]
            
                colored_etag = Fore.GREEN + etag + Style.RESET_ALL
                print(f"ETag of {url}: {colored_etag}")
                print()

                # Shodan
                shodan_result = consultar_shodan(shodan_api_key, etag)
                if shodan_result is not None:
                    print("{}{} Shodan results:{}".format(success_color, success_icon, reset_color))
                    print(shodan_result)
                else:
                    print(f"{failure_color}{failure_icon} Don't found result in Shodan.{reset_color}")

                # BinaryEdge
                binary_result = consultar_binaryedge(binaryedge_api_key, etag)
                if binary_result is not None:
                    print("{}{}BinaryEdge results:{}".format(success_color, success_icon, reset_color))
                    print(binary_result)
                else:
                    print(f"{failure_color}{failure_icon} Don't found result in BinaryEdge.{reset_color}")
                    
                # FOFA
                fofa_result = consultar_fofa(fofa_api_email, fofa_api_key, f"header=\"{etag}\"")
                if fofa_result:
                    print("{}{}FOFA results:{}".format(success_color, success_icon, reset_color))
                    print("{}".format(fofa_result[0]))
                else:
                    print(f"{failure_color}{failure_icon} Don't found result in FOFA.{reset_color}")
            else:
                print(f"Don't found etag in: {url}")
        else:
            print(f"Can't access to {url}. Error Code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"Request Error in {url}: {str(e)}")

# Main Menu
def mostrar_menu():
    while True:
        print()
        print("1. Analyze .onion URL (V3)")
        print("2. Analyze file with .onion URLs")
        print("0. Exit")
        print()
        seleccion = input("Choose an option: ")
        if seleccion == "0":
            sys.exit(0)
        elif seleccion == "1":
            url = input("Enter the .onion URL: ")
            process_url(url)
        elif seleccion == "2":
            archivo = input("Enter the file PATH: ")
            try:
                with open(archivo, "r") as file:
                    urls = file.readlines()
                    total_urls = len(urls)
                    print(f"Number of .onion URLs to analyze: {total_urls}")
                for i, url in enumerate(urls, start=1):
                    url = url.strip()
                    if url:
                        print(f"URL {i}/{total_urls}: {url}")
                        process_url(url)
            except FileNotFoundError:
                print("File don't found:", archivo)
        else:
            input("Invalid option. Press Enter to continue.")

if __name__ == "__main__":
    claves = cargar_claves_api('your_api_keys.cfg')
    shodan_api_key = claves['shodan_api_key']
    binaryedge_api_key = claves['binaryedge_api_key']
    fofa_api_email = claves['fofa_api_email']
    fofa_api_key = claves['fofa_api_key']
    mostrar_menu()