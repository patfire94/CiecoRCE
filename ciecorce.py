import argparse
import asyncio
import aiohttp
import os
import time
import logging
import json
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qs
from colorama import Fore, init, Style
from tqdm import tqdm
import requests

init(autoreset=True)

logging.basicConfig(level=logging.CRITICAL)
aiohttp_logger = logging.getLogger('aiohttp')
aiohttp_logger.setLevel(logging.CRITICAL)

banner = f"""
{Fore.GREEN}{Style.BRIGHT}
  ______   ______  _______
 /      \ /      \|       \\
|  $$$$$$|  $$$$$$| $$$$$$$\\
| $$__| $| $$___\$$ $$__/ $$
| $$    $ \$$    \| $$    $$
| $$$$$$$ _\$$$$$$| $$$$$$$\\
| $$  | $|  \__| $| $$__/ $$
| $$  | $$\$$    $| $$    $$
 \$$   \$$ \$$$$$$ \$$$$$$${Style.RESET_ALL}
CIECORCE - Blind RCE Scanner
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def read_file(file_path, as_json=False):
    try:
        with open(file_path, 'r') as file:
            return json.load(file) if as_json else [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file {file_path}: {e}")
        exit(1)

def parse_url(url):
    scheme, netloc, path, query, fragment = urlsplit(url)
    return scheme, netloc, path, parse_qs(query), fragment

def modify_url(url, param, payload):
    scheme, netloc, path, query_dict, fragment = parse_url(url)
    if param in query_dict:
        modified_query = query_dict.copy()
        # Append the payload to the existing parameter value
        modified_query[param] = [value + payload for value in query_dict[param]]
        query_string = urlencode(modified_query, doseq=True)
        return urlunsplit((scheme, netloc, path, query_string, fragment))
    return None

def save_results(file_path, results):
    with open(file_path, 'w') as file:
        for url, payload in results:
            file.write(f"{url} | Payload: {payload}\n")
    print(f"{Fore.GREEN}[+] Results saved to {file_path}")

def send_to_discord(webhook_url, url, payload):
    try:
        data = {"content": f"💉 Vulnerable to RCE 💉\n\nURL: {url}\nPayload: {payload}"}
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"{Fore.RED}[!] Error sending to Discord: {e}")

class BlindRCEScanner:
    def __init__(self, urls, payloads, concurrency, timeout, delay, headers, webhook, verbose):
        self.urls = urls
        self.payloads = payloads
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.headers = headers
        self.webhook = webhook
        self.verbose = verbose
        self.results = []

    async def test_url(self, sem, session, url, payload, param):
        async with sem:
            modified_url = modify_url(url, param, payload)
            if not modified_url:
                return
            try:
                start = time.time()
                async with session.get(modified_url, headers=self.headers, timeout=self.timeout) as response:
                    response_time = time.time() - start
                    if response_time >= self.delay:
                        print(f"{Fore.GREEN}[+] Vulnerable: {modified_url} | Payload: {payload}")
                        self.results.append((modified_url, payload))
                        if self.webhook:
                            send_to_discord(self.webhook, modified_url, payload)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error testing {url} with payload {payload}: {e}")

    async def scan(self):
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            for url in self.urls:
                scheme, netloc, path, query_dict, fragment = parse_url(url)
                for param in query_dict:
                    for payload in self.payloads:
                        tasks.append(self.test_url(sem, session, url, payload, param))
            await asyncio.gather(*tasks)

def main():
    clear_screen()
    print(banner)

    parser = argparse.ArgumentParser(description="CIECORCE - Blind RCE Scanner")
    parser.add_argument("-u", "--urls", required=True, help="File containing the list of URLs")
    parser.add_argument("-p", "--payloads", required=True, help="File containing the list of payloads")
    parser.add_argument("-o", "--output", default="ciecorce_output.txt", help="File to save the vulnerable URLs")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-d", "--delay", type=int, default=5, help="Minimum delay to consider as vulnerable")
    parser.add_argument("--headers", help="File with custom headers in JSON format")
    parser.add_argument("--webhook", help="Discord webhook URL for alerts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    urls = read_file(args.urls)
    payloads = read_file(args.payloads)
    headers = read_file(args.headers, as_json=True) if args.headers else {}

    scanner = BlindRCEScanner(
        urls=urls,
        payloads=payloads,
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
        headers=headers,
        webhook=args.webhook,
        verbose=args.verbose
    )

    asyncio.run(scanner.scan())

    print(f"{Fore.YELLOW}[i] Scan completed. Vulnerable URLs: {len(scanner.results)}")
    if scanner.results:
        save_results(args.output, scanner.results)

if __name__ == "__main__":
    main()
