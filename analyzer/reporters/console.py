from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ConsoleReporter:
    @staticmethod
    def print_header(text):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== {text} ==={Style.RESET_ALL}")

    @staticmethod
    def print_success(text):
        print(f"{Fore.GREEN}[+] {text}")

    @staticmethod
    def print_warning(text):
        print(f"{Fore.YELLOW}[!] WARNING: {text}")

    @staticmethod
    def print_danger(text):
        print(f"{Fore.RED}{Style.BRIGHT}[!] ALERT: {text}")