from unicorn import *
from unicorn.arm64_const import *
import unicorn.arm_const
import struct
import keystone

ABL_LOAD_ADDRESS = 0xFFFF0000F8800000
download_buffer = 0xFFFF000090700000
MEMORY_START = 0xFFFF0000F8000000
MEMORY_SIZE = 200 * 1024 * 1024
STACK_START = MEMORY_START + MEMORY_SIZE - 0x1000
INVALID_ADDR = 0xDEADBEEFDEADBEEF
kernel_aspace = 0xFFFF0000F8ACBC88


def gen_shellcode(data, address):
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    ret = ks.asm(data, address)
    return bytes(ret[0])


def hook_mem_read(uc, uc_mem_type, addr, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    data = uc.mem_read(addr, size)
    if user_data is not None:
        user_data.append((pc, addr, size, data))
    # print(f"MEMORY @{pc:08X} {addr:08x} {size:08x} {data}")
    return True


# Auto allocate pages of memory of size 10Mega on invalid memory access
def hook_mem_invalid_auto(uc, uc_mem_type, addr, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    start = addr & ~(10 * 1024 * 1024 - 1)
    if user_data:
        print(
            f"~~~~~~~~~~~~~~@{pc:x}                 mu.mem_map(0x{start:08x}, 10*1024*1024)"
        )
    uc.mem_map(start, 10 * 1024 * 1024)
    return True


def load_dumped_memory(mu):
    with open("memory_0xFFFF0000F8990000", "rb") as f:
        data = f.read()
        mu.mem_write(0xFFFF0000F8990000, data)


def mu_loader():

    # MAP file to offset
    with open("abl_210817", "rb") as f:
        data = f.read()

        try:
            # Initialize emulator in ARM mode
            mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

            mu.mem_map(MEMORY_START, MEMORY_SIZE)
            mu.mem_map(0xD8000000, 10 * 1024 * 1024)
            mu.mem_map(0xF8200000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFFFFFF19200000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFFFFFFF8200000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFF000080000000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFF000002000000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFFFFFF10000000, 10 * 1024 * 1024)
            mu.mem_map(0xFFFFFFFF20000000, 10 * 1024 * 1024)
            mu.mem_map(download_buffer, 1024 * 1024 * 5)  # download buffer

            # emulate machine code in infinite time
            mu.reg_write(UC_ARM64_REG_SP, STACK_START)

            # SIMD initialization
            SIMD_INIT = gen_shellcode(
                "mov x1, #(0x3 << 20);msr cpacr_el1, x1;isb", download_buffer
            )
            mu.mem_write(download_buffer, SIMD_INIT)

            # write machine code to be emulated to memory
            mu.mem_write(ABL_LOAD_ADDRESS, data)

            # load dumped memory
            load_dumped_memory(mu)

            mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid_auto)

            return mu

        except UcError as e:
            print("ERROR: %s" % e)
            return None


def read(vaddr):
    mu = mu_loader()
    d = mu.mem_read(vaddr, 8)
    v = struct.unpack("Q", d)[0]
    print(f"{d} {v:x}")


def get_pte_access(pte):
    return (pte >> 6) & 3


def get_pte_exec(pte):
    return not ((~pte) & 0x60000000000000 == 0)


def get_pte(vaddr):
    arch_mmu_query = 0xFFFF0000F880F5A0
    mu = mu_loader()
    if not mu:
        return

    mu.reg_write(UC_ARM64_REG_X30, INVALID_ADDR)
    mu.reg_write(UC_ARM64_REG_X0, kernel_aspace)
    mu.reg_write(UC_ARM64_REG_X1, vaddr)
    mu.reg_write(UC_ARM64_REG_X2, download_buffer)
    mu.reg_write(UC_ARM64_REG_X3, download_buffer + 8)

    access = []
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, user_data=access)
    mu.emu_start(arch_mmu_query, INVALID_ADDR, count=2000)
    x0 = mu.reg_read(UC_ARM64_REG_X0)
    if x0 == 0xFFFFFFFE:
        return 0, 0, 0, b"\x00" * 8

    # return last access of pte
    return list(filter(lambda k: k[0] == 0xFFFF0000F880F690, access))[-1]


def get_pte_info(vaddr):
    pc, addr, size, value = get_pte(vaddr)
    pte = struct.unpack("Q", value)[0]
    print(
        f"addr:{addr:x} pte:{pte:x} access:{get_pte_access(pte)} exec:{get_pte_exec(pte)}"
    )


if __name__ == "__main__":
    import fire

    fire.Fire(get_pte_info)
