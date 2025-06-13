import queue
import threading
import os
import urllib3

# Number of threads
threads = 10

# Get user input
target = input("Enter your target DNS address (e.g., http://example.com): ").strip()
directory = input("Enter your local directory to scan: ").strip()

# Ensure the target has the correct format
if not target.startswith(("http://", "https://")):
    target = "http://" + target  # Default to HTTP if no protocol is provided

# File types to ignore
filters = [".jpg", ".gif", ".png", ".css"]

# Change working directory to scan files
os.chdir(directory)

# Queue to store file paths
web_paths = queue.Queue()

# Walk through the directory and collect relevant paths
for root, _, files in os.walk("."):
    for file in files:
        remote_path = os.path.join(root, file)

        # Clean up the path for URL formatting
        if remote_path.startswith("."):
            remote_path = remote_path[1:]
        remote_path = remote_path.replace("\\", "/")  # Normalize for URL

        # Skip filtered file types
        if os.path.splitext(file)[1].lower() not in filters:
            web_paths.put(remote_path)

# Initialize HTTP manager
http = urllib3.PoolManager()

# Function to test remote URLs
def test_remote():
    while not web_paths.empty():
        try:
            path = web_paths.get_nowait()
        except queue.Empty:
            break

        url = f"{target}/{path.lstrip('/')}"  # Ensure no double slashes

        try:
            response = http.request("GET", url)
            if response.status == 200:
                print(f"[{response.status}] => {url}")
            else:
                print(f"[{response.status}] => {url}")
        except urllib3.exceptions.HTTPError as error:
            print(f"[ERROR] Request failed for {url}: {error}")

# Spawn threads
threads_list = []
for i in range(threads):
    print(f"Spawning thread: {i}")
    t = threading.Thread(target=test_remote)
    threads_list.append(t)
    t.start()

# Wait for all threads to finish
for t in threads_list:
    t.join()
