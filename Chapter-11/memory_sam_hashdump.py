import sys
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
from volatility.plugins.registry.registryapi import RegistryApi
from volatility.plugins.registry.lsadump import HashDump


MEMORY_IMAGE = "WinXPSP2.vmem"
PROFILE = "WinXPSP2x86"
VOL_PATH = "/Downloads/volatility-2.3.1"

sys.path.append(VOL_PATH)
registry.PluginImporter()
config = conf.ConfObject()

config.parse_options()
config.PROFILE = PROFILE
config.LOCATION = f"file://{MEMORY_IMAGE}"

registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)


reg_api = RegistryApi(config)
reg_api.populate_offsets()

sam_offset = None
system_offset = None

for offset, hive_path in reg_api.all_offsets.items():
    if hive_path.endswith("\\SAM"):
        sam_offset = offset
        print(f"[+] SAM Hive found at offset: 0x{offset:08X}")
    elif hive_path.endswith("\\system"):
        system_offset = offset
        print(f"[+] SYSTEM Hive found at offset: 0x{offset:08X}")

    if sam_offset and system_offset:
        break

if sam_offset and system_offset:
    config.sam_offset = sam_offset
    config.sys_offset = system_offset

    print("\n[+] Extracting user password hashes...")
    hash_dumper = HashDump(config)

    for user_hash in hash_dumper.calculate():
        print(user_hash)

else:
    print("[-] Could not locate both SYSTEM and SAM registry hives.")
