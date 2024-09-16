import configparser
import requests
import sys
import shodan
import mmh3
import hashlib
import pandas as pd
from colorama import Fore, Style

# API Keys
def cargar_claves_api(file):
    config = configparser.ConfigParser()
    config.read(file)
    claves = {}
    claves['shodan_api_key'] = config.get('API Keys', 'SHODAN_API_KEY')
    claves['binaryedge_api_key'] = config.get('API Keys', 'BINARYEDGE_API_KEY')
    claves['url_scanio_api_key'] = config.get('API Keys', 'URL_SCANIO_API_KEY')
    return claves

# Shodan
def consultar_shodan(api_key, html_hash):
    api = shodan.Shodan(api_key)
    try:
        # Query with the parameter html_hash
        query = 'http.html_hash:"{}"'.format(html_hash)
        results = api.search(query)
        if results['total'] > 0:
            # Create a list of dictionaries with the results
            data = []
            for match in results['matches']:
                info = {
                    'IP': match['ip_str'],
                    'País': match['location']['country_name'],
                    'ISP': match['isp'],
                    # You can add more fields here
                }
                data.append(info)
            
            # Create a DataFrame from the list of dictionaries
            df = pd.DataFrame(data)                
            return df
        else:
            return None
    except shodan.APIError as e:
        print('Shodan query error:', e)


# BinaryEdge
def consultar_binaryedge(api_key, html_hash):
    # API URL
    url = f"https://api.binaryedge.io/v2/query/search"

    # Query parameters
    params = {
        "query": f"htmlhash:{html_hash}"
    }

    # Request headers
    headers = {
        "X-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        # Try to make the request
        response = requests.get(url, params=params, headers=headers)

        # Verify the response status code
        if response.status_code == 200:
            # Get response data
            data = response.json()
            if "events" in data:
                results = data["events"]

                # Verify if there are results
                if len(results) > 0:
                    result_table = pd.DataFrame(columns=["IP", "Country"])
                    for result in results:
                        ip = result["target"]["ip"]
                        country = result["origin"]["country"]
                        # Add results to the table
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
        print("Connection error:", e)

# Urlscan.io
def consultar_urlscanio(api_key, query):
    url = "https://urlscan.io/api/v1/search/"
    headers = {
        "API-Key": api_key
    }
    params = {
        "q": query
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
        # Parse http:// or https://
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        claves = cargar_claves_api('your_api_keys.cfg')
        shodan_api_key = claves['shodan_api_key']
        binaryedge_api_key = claves['binaryedge_api_key']
        url_scanio_api_key = claves['url_scanio_api_key']

    # Request over Tor Network
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050'
        }
        response = session.get(url, stream=True, timeout=30)

        if response.status_code == 200:
            
            # Calculating the hash of the HTML content
            shodan_hash = mmh3.hash(response.content)
            censys_hash = hashlib.sha1(response.content).hexdigest()
            binaryedge_hash = hashlib.sha256(response.content).hexdigest()
            urlscanio_hash = hashlib.sha256(response.content).hexdigest()

            colored_hash_mmh3 = Fore.GREEN + str(shodan_hash) + Style.RESET_ALL
            colored_hash_sha1 = Fore.GREEN + str(censys_hash) + Style.RESET_ALL
            colored_hash_sha256 = Fore.GREEN + str(binaryedge_hash) + Style.RESET_ALL
            
            print()
            print("Hashes:")
            print(f"HTML Hash (MMH3): {colored_hash_mmh3}")
            print(f"HTML Hash (SHA1): {colored_hash_sha1}")
            print(f"HTML Hash (SHA256): {colored_hash_sha256}")

            colored_url = Fore.RED + url + Style.RESET_ALL
            print()
            print(f"Results of: {colored_url}")
            print()

            shodan_result = consultar_shodan(shodan_api_key, shodan_hash)
            if shodan_result is not None:
                print("Shodan results:")
                print(shodan_result)
            else:
                print("Don't found result in Shodan.")

            # BinaryEdge
            binaryedge_result = consultar_binaryedge(binaryedge_api_key, binaryedge_hash)
            if binaryedge_result is not None:
                print()
                print("BinaryEdge results:")
                print(binaryedge_result)
            else:
                print("Don't found result in BinaryEdge.")

            # Urlscan.io
            urlscanio_result = consultar_urlscanio(url_scanio_api_key, urlscanio_hash)
            if urlscanio_result:
                print()
                print("urlscan.io results:")
                print("country: {}".format(urlscanio_result['page']['country']))
                print("server: {}".format(urlscanio_result['page']['server']))
                print("IP: {}".format(urlscanio_result['page']['ip']))
                print("Domain: {}".format(urlscanio_result['page']['domain']))
                print("URL: {}".format(urlscanio_result['page']['url']))
            else:
                print("Don't found result in urlscan.io.")
        else:
            print(f"Can't entry in {url}. Code Status: {response.status_code}")                 
    except requests.exceptions.RequestException as e:
        print(f"Request error in {url}: {str(e)}")
    print()


# Principal Menu
def mostrar_menu():
    while True:
        print("1. Analyze .onion URL (V3)")
        print("2. Analyze file with .onion URLs")
        print("0. exit")
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
    mostrar_menu()
