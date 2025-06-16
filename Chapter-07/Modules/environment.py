import os
import json

def run():
    print("[*] Running environment module.")
    try:
        env_vars = dict(os.environ)
        return json.dumps(env_vars, indent=2)
    except Exception as e:
        return f"[!] environment module error: {e}"
