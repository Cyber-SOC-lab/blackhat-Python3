import base64
import json
import re
import socket
import urllib.parse

from burp import IBurpExtender, IContextMenuFactory
from java.net import URL
from java.util import ArrayList
from javax.swing import JMenuItem

# Replace with your valid Bing Search API key
bing_api_key = "YOURKEYHERE"

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        callbacks.setExtensionName("BHP Bing Lookup")
        callbacks.registerContextMenuFactory(self)
        print("[*] BHP Bing Lookup extension loaded")
        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_item = JMenuItem("Send to Bing", actionPerformed=self.bing_menu)
        menu_list.add(menu_item)
        return menu_list

    def bing_menu(self, event):
        selected_requests = self.context.getSelectedMessages()
        print(f"[*] {len(selected_requests)} request(s) selected.")

        for request in selected_requests:
            host = request.getHttpService().getHost()
            print(f"[*] Target Host: {host}")
            self.bing_search(host)

    def bing_search(self, host):
        try:
            # Check if host is an IP
            is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host)
            ip_address = host if is_ip else socket.gethostbyname(host)

            if is_ip:
                self.bing_query(f"'ip:{ip_address}'")
            else:
                self.bing_query(f"'ip:{ip_address}'")
                self.bing_query(f"'domain:{host}'")

        except Exception as e:
            print(f"[!] DNS lookup failed or Bing search error: {e}")

    def bing_query(self, query_string):
        print(f"[*] Executing Bing query: {query_string}")

        try:
            quoted_query = urllib.parse.quote(query_string)
            auth_token = base64.b64encode(f":{bing_api_key}".encode()).decode()

            http_request = (
                f"GET /Bing/Search/Web?$format=json&$top=20&Query={quoted_query} HTTP/1.1\r\n"
                "Host: api.datamarket.azure.com\r\n"
                "Connection: close\r\n"
                f"Authorization: Basic {auth_token}\r\n"
                "User-Agent: Blackhat Python\r\n\r\n"
            )

            response = self._callbacks.makeHttpRequest(
                "api.datamarket.azure.com", 443, True, http_request
            ).tostring()

            json_body = response.split("\r\n\r\n", 1)[1]

            results = json.loads(json_body)
            for site in results.get("d", {}).get("results", []):
                print("=" * 80)
                print(f"Title: {site['Title']}")
                print(f"URL: {site['Url']}")
                print(f"Description: {site['Description']}")
                print("=" * 80)

                url_obj = URL(site['Url'])
                if not self._callbacks.isInScope(url_obj):
                    print("[+] Adding site to Burp Scope.")
                    self._callbacks.includeInScope(url_obj)

        except Exception as e:
            print(f"[!] Error parsing Bing response: {e}")
