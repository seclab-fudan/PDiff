# Dataset Overview
We opensource AARCH64 test cases in our evaluation here.
Test cases are extracted from the kernel images from 8 vendors (D-Link, Huawei, Meizu, NETGEAR, Samsung, Google,
Oppo and Xiaomi). They run on various types of devices (routers,mobile phones and tablets) and migrated from different versions of Linux kernel (ranging from v3.4 to v4.9).

## Patch information
Information of the vulnerabilities for patch presence testing is summarized under different folders.
It contains the name of patch related functions, and their start and end address.
What's more, it contains the address of the external function calls. 

For  example:
```python
>>>> with open('./funcpkl/google/0467c397293993112bcccbe2b85044ba2e7b0851/CVE-2014-1739.pkl', 'rb') as f:
....     data = pickle.load(f)
....     
>>>> print(json.dumps(data, indent=4))
{
    "media_device_enum_entities": {
        "start_addr": 18446743798839713944,
        "end_addr": 18446743798839714284,
        "call": {
            "18446743798839713944": "media_device_enum_entities",
            "18446743798836098560": "memset",
            "18446743798836096736": "__copy_from_user",
            "18446743798839713552": "find_entity",
            "18446743798836134672": "strncpy",
            "18446743798836096992": "__copy_to_user",
            "18446743798833874620": "__stack_chk_fail"
        }
    }
}
```

## Dataset Useage
We extracted the rawbytes of patch related functions from vmlinux for ease of use.
You can make a simple analysis through capstone:

```python
>>>> from capstone import *
>>>> md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
>>>> with open('./funcpkl/google/0467c397293993112bcccbe2b85044ba2e7b0851/media_device_enum_entities.raw', 'rb') as f:
....     raw_data = f.read()
....     
>>>> for i in md.disasm(raw_data, func_min_addr):
....     print(i.address, '->', i.mnemonic, i.op_str)
....     
18446743798839713944 -> stp x29, x30, [sp, #-0x150]!
18446743798839713948 -> movz x2, #0x100
18446743798839713952 -> mov x29, sp
18446743798839713956 -> stp x19, x20, [sp, #0x10]
18446743798839713960 -> stp x21, x22, [sp, #0x20]
18446743798839713964 -> str x23, [sp, #0x30]
18446743798839713968 -> adrp x20, #0xffffffc001a1a000
18446743798839713972 -> mov x19, x0
18446743798839713976 -> add x0, x20, #0x128
18446743798839713980 -> mov x21, x1
18446743798839713984 -> ldr x1, [x0]
18446743798839713988 -> str x1, [x29, #0x148]
18446743798839713992 -> movz x1, #0
18446743798839713996 -> add x0, x29, #0x48
18446743798839714000 -> bl #0xffffffc00043f600
18446743798839714004 -> mov x0, sp
18446743798839714008 -> mov x1, x21
18446743798839714012 -> and x22, x0, #0xffffffffffffc000
18446743798839714016 -> ldr x2, [x22, #8]
18446743798839714020 -> adds x1, x1, #4
18446743798839714024 -> ccmp x1, x2, #2, lo
18446743798839714028 -> cset x0, ls
18446743798839714032 -> cbnz x0, #0xffffffc0007b20fc
18446743798839714036 -> movn x0, #0xd
...
18446743798839714216 -> cbz x2, #0xffffffc0007b20f4
18446743798839714220 -> movz x2, #0x100
18446743798839714224 -> add x1, x29, #0x48
18446743798839714228 -> mov x0, x21
18446743798839714232 -> bl #0xffffffc00043efe0
18446743798839714236 -> cbnz x0, #0xffffffc0007b20f4
18446743798839714240 -> add x20, x20, #0x128
18446743798839714244 -> ldr x2, [x29, #0x148]
18446743798839714248 -> ldr x1, [x20]
18446743798839714252 -> eor x1, x2, x1
18446743798839714256 -> cbz x1, #0xffffffc0007b21d8
18446743798839714260 -> bl #0xffffffc0002206bc
18446743798839714264 -> ldp x19, x20, [sp, #0x10]
18446743798839714268 -> ldp x21, x22, [sp, #0x20]
18446743798839714272 -> ldr x23, [sp, #0x30]
18446743798839714276 -> ldp x29, x30, [sp], #0x150
18446743798839714280 -> ret 
```

Also you can analysis it with angr.

```python
>>>> main_opts
{'arch': 'arm64', 'base_addr': 18446743798839713944, 'entry_point': 18446743798839713944, 'backend': 'blob'}
>>>> project = angr.Project('./funcpkl/google/0467c397293993112bcccbe2b85044ba2e7b0851/media_device_enum_entities.raw', auto_load_libs=False, main_opts=main_opts)
WARNING | 2020-11-03 10:52:21,352 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
```



