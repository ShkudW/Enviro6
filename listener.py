import ssl
from http.server import SimpleHTTPRequestHandler, HTTPServer
import argparse
import subprocess
import os
import random
from threading import Thread
from colorama import Fore, Style, init


init()

def generate_certificate(cert_file, key_file):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        try:
            print(f"{Fore.YELLOW}Generating SSL certificate...{Style.RESET_ALL}")
            process = subprocess.Popen([
                "openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
                "-x509", "-subj", "/CN=www.welcome.corp",
                "-keyout", key_file, "-out", cert_file
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            for line in iter(process.stdout.readline, b''):
                colored_line = ''.join(random.choice([
                    Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN
                ]) + chr(c) for c in line)
                print(colored_line, end='')
            
            process.stdout.close()
            process.wait()
            print(f"\n{Fore.GREEN}Certificate and key generated and saved to {cert_file} and {key_file}{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred during certificate creation: {e}")
            raise
    else:
        print(f"{Fore.GREEN}Certificate and key already exist. Using existing files.{Style.RESET_ALL}")

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('.ps1'):
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Set-Cookie', 'sessionid=bM2Bhj6QixtA4n9GcFB4Ne5o4MiQEmHvKVFB6v0vHPoIIHAvIh; Path=/; HttpOnly')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Pragma', 'no-cache')
            self.end_headers()
            ps1_file = self.path.lstrip('/')
            with open(ps1_file, 'rb') as file:
                self.wfile.write(file.read())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Nothing to see here!</h1></body></html>")

def run_http_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHandler)
    print(f"HTTP server is running on port {port}...")
    httpd.serve_forever()

def run_https_server(port, cert_file, key_file):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHandler)

    
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile=key_file,
                                   certfile=cert_file,
                                   server_side=True)
    
    print(f"HTTPS server is running on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP/HTTPS Server for serving PS1 files")
    parser.add_argument("-http_port", type=int, help="Port to run the HTTP server on")
    parser.add_argument("-https_port", type=int, help="Port to run the HTTPS server on")

    args = parser.parse_args()

    cert_file = "reception.pem"
    key_file = "reception.key"

    
    generate_certificate(cert_file, key_file)

    if args.http_port:
        http_thread = Thread(target=run_http_server, args=(args.http_port,))
        http_thread.start()

    if args.https_port:
        https_thread = Thread(target=run_https_server, args=(args.https_port, cert_file, key_file))
        https_thread.start()

    if args.http_port:
        http_thread.join()

    if args.https_port:
        https_thread.join()

