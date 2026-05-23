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

    @staticmethod
    def print_info(text):
        print(f"{Fore.BLUE}[~] {text}")

    @staticmethod
    def print_stream(text):
        import sys
        # Print on the same line to show a live stream of processing
        # Padding with spaces to overwrite previous longer lines
        padded_text = text.ljust(80)
        sys.stdout.write(f"\r{Fore.CYAN}[~] {padded_text}")
        sys.stdout.flush()

    @staticmethod
    def clear_stream():
        import sys
        sys.stdout.write(f"\r{' ' * 85}\r")
        sys.stdout.flush()