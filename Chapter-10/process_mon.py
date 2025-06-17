import win32con
import win32api
import win32security
import wmi
import os
import csv
import traceback

LOG_FILE = "process_monitor_log_file.csv"


def get_process_privileges(pid):
    try:
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token_handle = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
        privileges = win32security.GetTokenInformation(token_handle, win32security.TokenPrivileges)

        enabled_privs = []
        for priv_id, flags in privileges:
            if flags == win32con.SE_PRIVILEGE_ENABLED:
                priv_name = win32security.LookupPrivilegeName(None, priv_id)
                enabled_privs.append(priv_name)

        return "; ".join(enabled_privs) if enabled_privs else "None"
    except Exception as e:
        return "N/A"


def log_to_file(row):
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def main():
    if not os.path.exists(LOG_FILE):
        log_to_file(["Time", "User", "Executable", "CommandLine", "PID", "Parent PID", "Privileges"])

    c = wmi.WMI()
    process_monitor = c.Win32_Process.watch_for("Creation")

    while True:
        try:
            new_process = process_monitor()

            owner_info = new_process.GetOwner()
            proc_owner = f"{owner_info[0]}\\{owner_info[2]}"
            create_date = new_process.CreationDate
            executable = new_process.ExecutablePath or "N/A"
            cmdline = new_process.CommandLine or "N/A"
            pid = new_process.ProcessId
            parent_pid = new_process.ParentProcessId
            privileges = get_process_privileges(pid)

            log_row = [create_date, proc_owner, executable, cmdline, pid, parent_pid, privileges]
            print(", ".join(map(str, log_row)))
            log_to_file(log_row)

        except Exception as e:
            print("[!] Exception occurred:", e)
            traceback.print_exc()


if __name__ == "__main__":
    main()
