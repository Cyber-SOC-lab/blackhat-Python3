from burp import IBurpExtender, IContextMenuFactory

from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URL

import re
from html.parser import HTMLParser

# Custom HTML tag stripper
class Tagstripper(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.page_text = []

    def handle_data(self, data):
        self.page_text.append(data)

    def handle_comment(self, data):
        self.page_text.append(data)

    def strip(self, html):
        self.page_text = []
        self.feed(html)
        return " ".join(self.page_text)

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.hosts = set()
        self.wordlist = set(["password"])  # initial seed

        callbacks.setExtensionName("BHP Wordlist Generator")
        callbacks.registerContextMenuFactory(self)

        print("[*] BHP Wordlist extension loaded.")
        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Create Wordlist", actionPerformed=self.wordlist_menu))
        return menu_list

    def wordlist_menu(self, event):
        http_traffic = self.context.getSelectedMessages()
        for traffic in http_traffic:
            try:
                http_service = traffic.getHttpService()
                host = http_service.getHost()
                self.hosts.add(host)

                response = traffic.getResponse()
                if response:
                    html = self._helpers.bytesToString(response)
                    stripper = Tagstripper()
                    text = stripper.strip(html)

                    # Extract words (length 6–12 characters, no symbols)
                    words = re.findall(r'\b[a-zA-Z]{6,12}\b', text)
                    for word in words:
                        if word.lower() not in self.wordlist:
                            self.wordlist.add(word.lower())
            except Exception as e:
                print(f"[!] Error processing traffic: {e}")

        print("\n[+] Wordlist created with %d unique words:" % len(self.wordlist))
        for word in sorted(self.wordlist):
            print(word)
