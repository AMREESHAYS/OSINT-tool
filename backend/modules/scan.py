import subprocess

def scan_ports(target):
    try:
        result = subprocess.getoutput(f"nmap -F {target}")
        return result
    except Exception as e:
        return str(e)
