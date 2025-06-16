import os
import json

def run():
    print("[*] Running dirlister module.")
    try:
        current_dir = os.getcwd()
        files_info = []

        for f in os.listdir(current_dir):
            full_path = os.path.join(current_dir, f)
            if os.path.isfile(full_path):
                size = os.path.getsize(full_path)
                mtime = os.path.getmtime(full_path)
                files_info.append({"file": f, "size": size, "modified": mtime})
            else:
                files_info.append({"dir": f})

        return json.dumps(files_info, indent=2)

    except Exception as e:
        return f"[!] dirlister error: {e}"
