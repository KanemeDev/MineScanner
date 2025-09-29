from pythonping import ping
import requests as r
import socket
from datetime import datetime
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from mcstatus import JavaServer
from dotenv import load_dotenv
import os
import re
import time
from tqdm import tqdm
from colorama import init as colorama_init, Fore, Style

load_dotenv()
colorama_init(autoreset=True)
write_lock = threading.Lock()
parser = argparse.ArgumentParser()
webhook = os.environ.get("WEBHOOK_URL")

#args init
parser.add_argument('-ip', type=str, dest='iprange', required=True, help='IP range to scan (e.g. 192.168.*.*)')
parser.add_argument('-p', type=str, dest='port_range', default='25560-25580', help='Port range for scanning')
parser.add_argument('-t', type=int, dest='max_workers', default=50, help='Max worker threads for scanning')
parser.add_argument('-w', type=bool, dest='webhook', default=False, help='Discord webhook result file sender')

#initialize and start scanning
def init():
    print(Fore.MAGENTA + "-- MineScanner --" + Style.RESET_ALL + "\n")
    open("result.txt", "w+", encoding='utf-8').close()
    
    #args parse
    args = parser.parse_args()
    iprange = args.iprange
    port = args.port_range
    port_range = port.split('-')
    max_workers = args.max_workers
    webhook_sender = args.webhook
    if webhook is None and webhook_sender:
        print("No webhook URL found in .env file")
        return
    
    if not iprange:
        print("No IP range provided")
        return

    print(Fore.BLUE + f"IP Range: {iprange}" + Style.RESET_ALL + "\n")

    t1 = time.time()
    ips = expand_iprange(iprange)
    SUBMIT_DELAY = 0.03
    progress = tqdm(total=len(ips), desc='IPs', ncols=90, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] • {rate_fmt}', colour='green')
    total_servers = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip in ips:
            future = executor.submit(scan_ip, ip, port_range)
            futures[future] = ip
            time.sleep(SUBMIT_DELAY)
        try:
            for future in as_completed(futures):
                try:
                    found = future.result()
                except Exception as e:
                    tqdm.write(Fore.RED + f"Error scanning {futures[future]}: {e}" + Style.RESET_ALL)
                    found = 0
                total_servers += found if isinstance(found, int) else 0
                progress.update(1)
                progress.set_postfix(servers=total_servers, refresh=False)
        except KeyboardInterrupt:
            tqdm.write(Fore.YELLOW + "Scan interrupted by user" + Style.RESET_ALL)
            executor.shutdown(wait=False)
        finally:
            progress.close()
    
    t2 = time.time()
    total = round(t2 - t1, 2)
    minutes = total // 60
    seconds = total % 60
    total = f"{int(minutes)} minutes {int(seconds)} seconds" if minutes else f"{int(seconds)} seconds"
    if webhook_sender:
        with open("result.txt", "r", encoding='utf-8') as f:
            content = f.read()
        if len(content) > 0:
            with open("result.txt", "rb") as f:
                r.post(webhook, data={"content": f"Scan: **{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**, {int(len(content.splitlines())/2)} server found.\nRan for **{total}** with **{max_workers} workers**."}, files={"result.txt": f})
            print(Fore.GREEN + "Scan complete. Results saved in result.txt" + Style.RESET_ALL)
        else:
            r.post(webhook, json={"content": f"Scan: **{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**, no result found."})
            print(Fore.GREEN + "Scan complete. Results saved in result.txt" + Style.RESET_ALL)
            print(Fore.YELLOW + "No results to send." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "Scan complete. Results saved in result.txt" + Style.RESET_ALL)
    print(Fore.CYAN + f"Total scan time: {total} seconds" + Style.RESET_ALL)
    print(Fore.CYAN + f"Total servers found: {total_servers}" + Style.RESET_ALL)

#write results in result.txt
def write_result(text: str):
    try:
        with write_lock:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(text + "\n")
    except Exception as e:
        print(f"Failed to write: {e}")

#ip range expansion
def expand_iprange(iprange: str):
    iprange = iprange.strip()
    parts = iprange.split('.')
    if len(parts) != 4:
        return [iprange]

    octet_values = []
    for p in parts:
        p = p.strip()
        if p == '*':
            octet_values.append([str(i) for i in range(256)])
        else:
            octet_values.append([p])

    ips = []
    for a in octet_values[0]:
        for b in octet_values[1]:
            for c in octet_values[2]:
                for d in octet_values[3]:
                    ips.append(f"{a}.{b}.{c}.{d}")

    return ips

#scan ports with threading
def scan_ip(ip: str, port_range):
    response = ping(ip, count=1, timeout=2)

    if response.success():
        tqdm.write(Fore.CYAN + f"MineScanner: {ip} is valid, scanning... (started at {datetime.now().strftime('%H:%M:%S')})" + Style.RESET_ALL)
        ip_found = 0

        try:
            def port_worker(port: int):
                nonlocal ip_found
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        try:
                            server = JavaServer.lookup(f"{ip}:{port}")
                            try:
                                status = server.status(timeout=3)
                            except TypeError:
                                try:
                                    status = server.status(request_timeout=3)
                                except TypeError:
                                    status = server.status()

                            online = getattr(status.players, 'online', 0) if status.players is not None else 0
                            maximum = getattr(status.players, 'max', 0) if status.players is not None else 0
                            version = getattr(status.version, 'name', 'N/A') if status.version is not None else 'N/A'
                            motd_raw = getattr(status, 'description', None) or getattr(status, 'motd', None)
                            motd_parse = str(motd_raw) if motd_raw is not None else 'N/A'
                            motd = re.sub(r'§.', '', motd_parse).replace('\\n', ' ').strip() if motd_parse else 'N/A'
                            server_ip = ip
                            server_port = port

                            port_msg = f"{server_ip}:{server_port} | Players: {online}/{maximum} | Version: {version} | MOTD: {motd}"
                        except Exception:
                            return
                        tqdm.write(Fore.GREEN + port_msg + Style.RESET_ALL)
                        write_result(port_msg)
                        ip_found += 1
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                    

            with ThreadPoolExecutor(max_workers=10) as pexec:
                port_futures = [pexec.submit(port_worker, port) for port in range(int(port_range[0]), int(port_range[1]))]
                for pf in as_completed(port_futures):
                    try:
                        pf.result()
                    except Exception as e:
                        tqdm.write(Fore.RED + f"Error with {ip}: {e}" + Style.RESET_ALL)
        except KeyboardInterrupt:
            raise
        except socket.gaierror:
            tqdm.write(Fore.RED + "Couldn't connect to server" + Style.RESET_ALL)
        except socket.error:
            tqdm.write(Fore.RED + "Couldn't connect to server" + Style.RESET_ALL)
        return ip_found
    else:
        tqdm.write(Fore.YELLOW + f"MineScanner: {ip} is unreachable" + Style.RESET_ALL)
        return 0


if __name__ == '__main__':
    init()