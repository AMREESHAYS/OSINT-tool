import subprocess

def take_screenshot(url):
    try:
        filename = url.replace("http://", "").replace("https://", "") + ".png"
        subprocess.getoutput(f"webkit2png {url} -o {filename}")
        return filename
    except:
        return None
