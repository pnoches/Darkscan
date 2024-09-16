import html_hash
import favicon_hash
import etag
import sys
from colorama import Fore, Style

def process_url_all(url):
    subrayado_color = Fore.LIGHTRED_EX + '*' + Style.RESET_ALL
    print()
    title_color = Fore.BLUE + 'Executing Hash Html Technique' + Style.RESET_ALL
    print(f"{subrayado_color*40}\n{title_color}\n{subrayado_color*40}")
    html_hash.process_url(url)
    print()
    title_color = Fore.BLUE + 'Executing Hash Fivicon Technique' + Style.RESET_ALL
    print(f"{subrayado_color*40}\n{title_color}\n{subrayado_color*40}")
    favicon_hash.process_url(url)
    print()
    title_color = Fore.BLUE + 'Executing Etag Technique' + Style.RESET_ALL
    print(f"{subrayado_color*40}\n{title_color}\n{subrayado_color*40}")
    etag.process_url(url)
    print()
    print("End of all techniques.")

# Menú principal
def mostrar_menu_all():
    while True:
        print("1. Analyze .onion URL (V3)")
        print("2. Analyze file with .onion URLs")
        print("0. Exit")
        print()
        seleccion = input("Choose an option: ")
        if seleccion == "0":
            sys.exit(0)
        elif seleccion == "1":
            url = input("Enter the .onion URL: ")
            process_url_all(url)
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
                        process_url_all(url)
            except FileNotFoundError:
                print("File don't found:", archivo)
        else:
            input("Invalid option. Press Enter to continue.")

mostrar_menu_all()
