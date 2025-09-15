import requests as r
from pythonping import ping
import socket
from datetime import datetime
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

write_lock = threading.Lock()
parser = argparse.ArgumentParser()

#args init
parser.add_argument('-ip', type=str, dest='iprange', required=True, help='IP range to scan (e.g. 192.168.*.*)')
parser.add_argument('-t', type=int, dest='max_workers', default=50, help='Max worker threads for scanning')

#initialize and start scanning
def init():
    print("-- MineScanner --\n")
    open("result.txt", "w", encoding='utf-8').close()

    #args parse
    args = parser.parse_args()
    iprange = args.iprange
    max_workers = args.max_workers

    if not iprange:
        print("No IP range provided")
        return

    print(f"IP Range: {iprange}\n")

    ips = expand_iprange(iprange)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ips}
        try:
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error scanning {futures[future]}: {e}")
        except KeyboardInterrupt:
            print("Scan interrupted by user")
            executor.shutdown(wait=False)

#write results in result.txt
def write_result(text: str):
    try:
        with write_lock:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(text + "\n")
    except Exception as e:
        print(f"Failed to write : {e}")

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
def scan_ip(ip: str):
    response = ping(ip, count=1, timeout=2)

    if response.success():
        API = "https://api.mcsrvstat.us/3/"
        msg = f"MineScanner | {ip} | found"
        print(msg + "\n")

        print("-" * 50)
        print("Scanning Target: " + ip)
        print("Scanning started at: " + str(datetime.now()))
        print("-" * 50)

        try:
            def port_worker(port: int):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        try:
                            resp = r.get(f"{API}{ip}:{port}", timeout=3)
                            mc = resp.json()
                        except Exception as e:
                            mc = {}
                            print(f"Failed to get server info for {ip}:{port}: {e}")

                        players = mc.get('players', {})
                        online = players.get('online', 0)
                        maximum = players.get('max', 0)
                        version = mc.get('version', 'N/A')
                        server_ip = mc.get('ip', ip)
                        server_port = mc.get('port', port)

                        port_msg = (
                            f"{server_ip}:{server_port} | Minecraft Server\n"
                            f"Players: {online}/{maximum} | Version: {version}\n"
                        )

                        print(port_msg)
                        write_result(port_msg)

                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            with ThreadPoolExecutor(max_workers=10) as pexec:
                port_futures = [pexec.submit(port_worker, port) for port in range(25560, 25580)]
                for pf in as_completed(port_futures):
                    try:
                        pf.result()
                    except Exception as e:
                        print(f"Port error on {ip}: {e}")
        except KeyboardInterrupt:
            raise
        except socket.gaierror:
            print("Couldn't connect to server")
        except socket.error:
            print("Couldn't connect to server")
    else:
        print(f"MineScanner : {ip}, is unreachable\n")


if __name__ == '__main__':
    init()