import os
from colorama import Fore, Style

#Funtion to print a box with a message
def print_box(content):
    width = len(content) + 4
    border = "+" + "-" * (width - 2) + "+"
    print(border)
    print("|" + content.center(width - 2) + "|")
    print(border)

# Function to show the banner
def mostrar_banner():
    banner = """
    ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║  ██║███████║██████╔╝█████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗███████║╚██████╗██║  ██║██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                                                                
    """
    autor = "Author: P4bl0 N."
    github = "GitHub: https://github.com/pnoches"
    version = "Version: 1.0.0"
    descripcion = "Description: Automate information gathering and deanonimize Tor hidden services."
    print(banner)
    print(autor)
    print(github)
    print(version)
    print(descripcion)
    print()

# Function to show the main menu
def mostrar_menu():
    opciones = ["Html Hash", "Favicon Hash", "Etag", "Try all Techniques"]
    while True:
        os.system('clear')  # On windows change 'clear' to 'cls'
        mostrar_banner()    
        print("Main Menu:")
        print()
        for i, opcion in enumerate(opciones, start=1):
            print(f"{i}. {opcion}")
        print("0. Exit")
        print()
        seleccion = input("Choose an option: ")
        if seleccion == "0":
            break
        elif seleccion.isdigit() and 1 <= int(seleccion) <= len(opciones):
            opcion_seleccionada = opciones[int(seleccion) - 1]
            cargar_script(opcion_seleccionada)
        else:
            input("Invalid option. Press Enter to continue.")

# Function to load the selected script
def cargar_script(opcion):
    script_file = ""
    if opcion == "Html Hash":
        script_file = "scripts/html_hash.py"
    elif opcion == "Favicon Hash":
        script_file = "scripts/favicon_hash.py"
    elif opcion == "Etag":
        script_file = "scripts/etag.py"
    elif opcion == "Try all Techniques":
        script_file = "scripts/all_scripts.py"

    if os.path.exists(script_file):
        os.system('clear')  # In windows change 'clear' to 'cls'
        mostrar_banner()
        opcion_color = Fore.LIGHTRED_EX + opcion + Style.RESET_ALL
        print(f"Technique to try: {opcion_color}")
        print()
        # Execute the selected script
        os.system(f"python {script_file}")
        input("Press enter to return to the main menu.")
    else:
        os.system('clear')  # on windows change 'clear' to 'cls'
        mostrar_banner()
        input("Press enter to return to the main menu")

if __name__ == "__main__":
    # Main function
    mostrar_menu()
    