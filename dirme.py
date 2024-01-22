import requests
import argparse
import pyfiglet
import urllib.parse
from colorama import Fore
from time import sleep

fr = Fore.RED
fg = Fore.GREEN
f_reset = Fore.RESET

parser = argparse.ArgumentParser(description="Fuzzy vulnerability testing tool.")

parser.add_argument('-u', '--url', required=True,
                        help='Target URL: https://example.com/FUZZ')
parser.add_argument('-sc', '--status_code', required=False,
                        help='Expected response status code (200, 301, 404, 403, 500)')
parser.add_argument('-e', '--extension', required=False,
                        help='File extension')
parser.add_argument('-w', '--wordlist', required=True,
                        help='Wordlist file for fuzzing')

args = parser.parse_args() 


class DefDirMe:
    def __init__(self, host, wordlist, extension) -> None:
        self.host = host
        self.wordlist = wordlist
        self.session = requests.Session()
        self.extension = extension
        self.count = 0
        pass


    def banner(self):
        print('\n')
        banner = pyfiglet.Figlet(font='5lineoblique')
        print(banner.renderText('Dirme'))
        print('v1 ------- Made By Pixel.Def')
        print('-' * 50)
        sleep(1)
        print(f':: Payload:      : {self.wordlist}')
        print(f':: URL:          : {self.host}')
        print(f':: Extension/s:    : {self.extension if not self.extension is None else "---"}')
        print('-' * 50, '\n')
        print('[+] Warning: This is directory-bruteforce testing software, do not use it without prior permission because this is an illegal action.')
        print('Use only in authorized environments and that have full control, I am not responsible for misuse of the application.\n')
        sleep(2)


    def read_wordlist(self):
        print('[+] Generating Wordlist!\n')
        sleep(2)
        with open(self.wordlist, 'rb') as file:
            payloads = [line.decode('utf-8').strip() for line in file.readlines()]
    
        return payloads
    

    def validate_url(self):
        try:
            result = urllib.parse.urlparse(self.host)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False


    def check_host(self):
        http_protocols = ['http://', 'https://']
        
        if self.host.startswith('http://') or self.host.startswith('https://'):
            return True
        
        if not self.host.startswith('http://') or not self.host.startswith('https://'):
            for protocol in http_protocols:
                host = protocol + self.host 
                try:
                    response = self.session.get(host)
                    if response.status_code == 200:
                        return True
                except requests.exceptions.ConnectionError:
                    pass
            return False
        

    def check_for_forbbiden_status_code(self, status_code):
        if status_code == 403:
            if self.count == 3:
                print('\n[+] All response from this host return 403')
                exit(1)
            self.count += 1


    def dirbme(self, payloads):
        for payload in payloads:
            if len(payload) > 20:
                continue
            
            if self.extension is None:
                if self.host.endswith('/'):
                     dirb = f'{self.host}{payload}'
                     print(f'\r\r{f_reset + self.host + f_reset}{fg + payload.ljust(30) + f_reset}', end='', flush=True)
                else:
                    dirb = f'{self.host}/{payload}'
                    print(f'\r\r{f_reset + self.host + f_reset}/{fg + payload.ljust(30) + f_reset}', end='', flush=True)
                try:
                    response = self.session.get(dirb, timeout=10)
                    response_status_code = response.status_code

                    self.check_for_forbbiden_status_code(response_status_code)

                    if response_status_code >= 200 and response_status_code < 404:
                        print(f'\r{f_reset + dirb + f_reset} - [+] {response_status_code}')
                except requests.exceptions.ConnectionError:
                    print(f'[+] Invalid URL format. Please provide a valid URL. => {self.host}')
                    exit(1)
                except requests.exceptions.ReadTimeout:
                    pass

            else:
                for extension in self.extension.split(','):
                    if self.host.endswith('/'):
                        dirb = f'{self.host}{payload}{extension}'
                        print(f'\r\r{f_reset + self.host + f_reset}{fg + payload.ljust(30) + f_reset}{extension.ljust(5)}', end='', flush=True)
                    else:
                        dirb = f'{self.host}/{payload}{extension}'
                        print(f'\r\r{f_reset + self.host + f_reset}/{fg + payload.ljust(30) + f_reset}{extension.ljust(5)}', end='', flush=True)
                    try:
                        response = self.session.get(dirb, timeout=10)
                        response_status_code = response.status_code

                        self.check_for_forbbiden_status_code(response_status_code)

                        if response_status_code >= 200 and response_status_code < 404:
                            print(f'\r{f_reset + dirb + f_reset} - [+] {response_status_code}')
                    except requests.exceptions.ConnectionError:
                            print(f'[+] Invalid URL format. Please provide a valid URL. => {self.host}')
                            exit(1)
                    except requests.exceptions.ReadTimeout:
                        pass

                
def main():
    host = args.url
    wordlist =  args.wordlist
    extension = args.extension

    dirbme = DefDirMe(host, wordlist, extension)
    dirbme.banner()

    if not extension is None and not extension.startswith('.'):
        print('[+] Invalid extension format. Usage exemple: .php,.html,.txt')
        exit(1) 

    if not dirbme.validate_url():
        print('[+] Invalid URL format. Please provide a valid URL.')
        exit(1)

    if not host.startswith('http://') and not host.startswith('https://'):              
        print('[+] Missing http:// or https://')
        exit(1)

    if not dirbme.check_host():
        print('[+] Host is down!')
        exit(1)
    
    payloads = dirbme.read_wordlist()
    dirbme.dirbme(payloads)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n[+] App Aborted!')
        exit(1)