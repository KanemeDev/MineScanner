# MineScanner

A multi-threaded Minecraft server scanner for IP ranges  
Useful for checking if certain ports are open and quickly detecting active servers

---

## Download  

You can download MineScanner from the [releases page](https://github.com/KanemeDev/MineScanner/releases)   

---

## Usage  

Python is required to run the scanner.  
Running it on a Linux VPS or dedicated server is strongly recommended for the best performance.

To run it:  
```bash
sudo py main.py -ip 127.80.*.* -t 50 -p 25560-25590

-ip = your ip range with with * instead of 0
exemple: 127.80.0.0/16 -> 127.80.*.*

-t = the number of threads (default: 50)

-p = port range (default: 25560-25580)
```
---
