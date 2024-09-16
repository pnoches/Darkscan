import mmh3
import hashlib
import requests
import shodan
import configparser
import sys
import base64
from tqdm import tqdm
import pandas as pd
from colorama import Fore, Style
from bs4 import BeautifulSoup
import urllib.parse

# API Keys from config.cfg
def cargar_claves_api(file):
    config = configparser.ConfigParser()
    config.read(file)
    claves = {}
    claves['shodan_api_key'] = config.get('API Keys', 'SHODAN_API_KEY')
    claves['binaryedge_api_key'] = config.get('API Keys', 'BINARYEDGE_API_KEY')
    claves['fofa_api_email'] = config.get('API Keys', 'FOFA_API_EMAIL')
    claves['fofa_api_key'] = config.get('API Keys', 'FOFA_API_KEY')
    claves['url_scanio_api_key'] = config.get('API Keys', 'URL_SCANIO_API_KEY')
    return claves

# Shodan
def consultar_shodan(api_key, hash):
    api = shodan.Shodan(api_key)
    try:
        results = api.search(f"http.favicon.hash:{hash}")
         # Verify if there are results
        if results['total'] > 0:
            data = []
            for match in results['matches']:
                info = {
                    'IP': match['ip_str'],
                    'País': match['location']['country_name'],
                    'ISP': match['isp'],
                    # 
                }
                data.append(info)
            
            # Add results to the table
            df = pd.DataFrame(data)
            df.index+=1                
            return df
        else:
            return None
    except shodan.APIError as e:
        print('Shodan query Error:', e)

# BinaryEdge
def consultar_binaryedge(api_key, hash):
    url = "https://app.binaryedge.io/services/query"
    params = {
        "query": f"web.favicon.mmh3:{hash}"
    }
    headers = {
        "X-Key": api_key
    }
    response = requests.get(url, params=params, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'events' in data:
            if len(data['events']) > 0:
                return data
    return None


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

# Process the URL
def process_url(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        claves = cargar_claves_api('your_api_keys.cfg')
        shodan_api_key = claves['shodan_api_key']
        binaryedge_api_key = claves['binaryedge_api_key']
        fofa_api_email = claves['fofa_api_email']
        fofa_api_key = claves['fofa_api_key']
        url_scanio_api_key = claves['url_scanio_api_key']

        #Request over Tor Network
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050'
        }
        response = session.get(url, stream=True, timeout=30)

        if response.status_code == 200:
            block_size = 1024
            favicon = b""
            favicon_url = None

            # Download the favicon and show the progress bar
            for data in response.iter_content(block_size):
                favicon += data

            # Use BeautifulSoup to parse the HTML of the page
            soup = BeautifulSoup(favicon, 'html.parser')

            # List of possible rel attribute values for favicon
            rel_values = ['shortcut icon', 'icon', 'mask-icon', 'apple-touch-icon', 'apple-touch-icon-precomposed', 'manifest']

            # Find the element containing the link to the favicon
            favicon_tag = soup.find('link', rel=rel_values)

            if favicon_tag:
                # Get the URL of the favicon
                favicon_url = favicon_tag.get('href')
                url = urllib.parse.urlparse(url)
                base_scheme = url.scheme
                base_domain = url.netloc.rstrip('/')
                parsed_icon_url = urllib.parse.urlparse(favicon_url)

                if not parsed_icon_url.scheme:
                    if not parsed_icon_url.path.startswith('/'):
                        favicon_url = f"{base_scheme}://{base_domain}/{favicon_url}"
                    else:
                        favicon_url = f"{base_scheme}://{base_domain}{favicon_url}"

            # Store the content in a separate variable
            favicon_content = b""

            # Make a request to the favicon URL
            if favicon_url is not None:
                if favicon_url.startswith("data:image"):
                    favicon_content = base64.b64decode(favicon_url.split(",")[1])
                    print("Favicon in Base64")
                else:
                        print("favicon found at:", favicon_url)
                        favicon_response = session.get(favicon_url, stream=True, timeout=30)
                        # Get the size of the favicon content for progress bar
                        favicon_size = int(favicon_response.headers.get('content-length', 0))
                        progress_bar_favicon = tqdm(total=favicon_size, unit='B', unit_scale=True, desc='Downloading favicon')

                        # Download the favicon and display the progress bar
                        for data in favicon_response.iter_content(block_size):
                            progress_bar_favicon.update(len(data))
                            favicon_content += data
                        progress_bar_favicon.close()

            # Calculate the hash of the favicon
            if favicon_content is not None and favicon_content != b"":
                mmh3_hash = mmh3.hash(favicon_content)
                sha256_hash = hashlib.sha256(favicon_content).hexdigest()
                md5_hash = hashlib.md5(favicon_content).hexdigest()

                # Show favicon hashes Type
                print()
                print("Hashes:")

                colored_hash_mmh3 = Fore.GREEN + str(mmh3_hash) + Style.RESET_ALL
                colored_hash_sha256 = Fore.GREEN + str(sha256_hash) + Style.RESET_ALL
                colored_hash_md5 = Fore.GREEN + str(md5_hash) + Style.RESET_ALL

                print("Favicon MMH3 hash:", colored_hash_mmh3)
                print("Favicon SHA256 hash:", colored_hash_sha256)
                print("Favicon MD5 hash:", colored_hash_md5)
                print()

                success_icon = "✔"
                failure_icon = "✗"
                
                success_color = "\033[92m"  # Green for success
                failure_color = "\033[91m"  # Red for failure
                reset_color = "\033[0m"

                # Shodan
                shodan_result = consultar_shodan(shodan_api_key, mmh3_hash)
                if shodan_result is not None:
                    print("{}{} Shodan results:{}".format(success_color, success_icon, reset_color))
                    print(shodan_result)
                else:
                    print("{}{} Don't found result in Shodan.{}".format(failure_color, failure_icon, reset_color))

                # BinaryEdge
                binaryedge_result = consultar_binaryedge(binaryedge_api_key, mmh3_hash)
                if binaryedge_result:
                    print("{}{} BinaryEdge results:{}".format(success_color, success_icon, reset_color))
                    print("{}".format(binaryedge_result['events'][0]['target']['ip']))
                else:
                    print("{}{} Don't found result in BinaryEdge.{}".format(failure_color, failure_icon, reset_color))
                
                #FOFA
                fofa_result = consultar_fofa(fofa_api_email, fofa_api_key, f"icon_hash=\"{mmh3_hash}\"")
                if fofa_result is not None:
                    print("{}{} FOFA results:{}".format(success_color, success_icon, reset_color))
                    print("{}".format(fofa_result[0]))
                else:
                    print("{}{} Don't found result in FOFA.{}".format(failure_color, failure_icon, reset_color))

                # Urlscan.io
                urlscanio_result = consultar_urlscanio(url_scanio_api_key, sha256_hash)
                if urlscanio_result is not None:
                    print("{}{} urlscan.io results:{}".format(success_color, success_icon, reset_color))
                    print("{}".format(urlscanio_result['page']['domain']))
                else:
                    print("{}{} Don't found result in urlscan.io.{}".format(failure_color, failure_icon, reset_color))
            else:
                colored_wrong = Fore.RED + "✗" + Style.RESET_ALL
                colored_msg = Fore.WHITE + "Can't download the favicon. The onion site don't have a favicon." + Style.RESET_ALL
                print(colored_wrong, colored_msg)

        else:
            print("Can't download the favicon. The onion site don't have a favicon.")
        
    except requests.exceptions.InvalidURL as e:
        print("Invalid URL.")
    except requests.exceptions.MissingSchema as e:
        print("ERROR: Invalid URL. Make sure the url is correct.")
    except requests.ConnectionError as e:
        print("ERROR: Can't connect to the onion server. Check your internet connection, or TOR service.")

# Main menu
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


if __name__ == '__main__':
    mostrar_menu()
