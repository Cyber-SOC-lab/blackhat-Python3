import urllib3
import threading
import queue
import urllib.parse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize HTTP connection pool
http = urllib3.PoolManager()

def build_wordlist(wordlist_file, resume_point=None):
    with open(wordlist_file, "rb") as fd:
        raw_words = fd.readlines()

    words = queue.Queue()
    found_resume = False

    for word in raw_words:
        word = word.strip().decode("utf-8")

        if resume_point:
            if found_resume:
                words.put(word)
            elif word == resume_point:
                found_resume = True
                print(f"[+] Resuming wordlist from: {resume_point}")
        else:
            words.put(word)

    return words


def dir_bruter(word_queue, extensions=None):
    while not word_queue.empty():
        attempt = word_queue.get()
        attempt_list = []

        if "." not in attempt:
            attempt_list.append(f"/{attempt}/")
        else:
            attempt_list.append(f"/{attempt}")

        if extensions:
            for ext in extensions:
                attempt_list.append(f"/{attempt}{ext}")

        for brute in attempt_list:
            url = f"{target_url}{urllib.parse.quote(brute)}"
            headers = {"User-Agent": user_agent}

            try:
                response = http.request("GET", url, headers=headers)

                if response.status != 404:
                    print(f"[{response.status}] => {url}")

            except urllib3.exceptions.HTTPError as e:
                print(f"[!] Error: {e} => {url}")
            except Exception as e:
                print(f"[!] Unexpected Error: {e} => {url}")


# Configuration
threads = 5
target_url = input("🌐 Enter the target URL (e.g., http://example.com): ").strip().rstrip('/')
wordlist_file = "Enter the file path of wordlist, eg all.txt"
resume = None  # Optional: "admin"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"

# Load wordlist
word_queue = build_wordlist(wordlist_file, resume)
extensions = [".php", ".bak", ".orig", ".inc"]

# Launch brute-force threads
for i in range(threads):
    t = threading.Thread(target=dir_bruter, args=(word_queue, extensions))
    t.start()
