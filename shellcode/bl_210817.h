typedef long unsigned int uint64_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef uint8_t bool;

typedef uint64_t size_t;
typedef uint64_t uint;

typedef uint64_t status_t;
typedef uint64_t vaddr_t;
typedef uint64_t paddr_t;
typedef uint64_t pte_t;

#define true (1)

#define SHELLCODE_MAIN  __attribute__((__section__(".shellcode_entry")))

typedef struct {
	uint64_t tt_phys;
	pte_t * tt_virt;
	uint64_t flags;
	uint64_t base;
	uint64_t size;
} arch_aspace_t;
extern arch_aspace_t kernel_aspace;

extern status_t arch_mmu_query(arch_aspace_t *aspace, vaddr_t vaddr, paddr_t *paddr, uint *flags);
#if 0
#define LTRACEF printf
#else
#define LTRACEF(...) do {} while(0)
#endif

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#define PANIC_UNIMPLEMENTED do { \
printf("error unimplemented\n");\
return 0;\
} while (0)


#define ASSERT(x) do {\
if (!(x)) {\
	printf("assert failed %s",STR(x)); \
	PANIC_UNIMPLEMENTED; \
}} while(0)

#define DEBUG_ASSERT(x) ASSERT(x)


#define ERR_NOT_FOUND (-2)
#define ERR_OUT_OF_RANGE (-37)

#define MMU_PTE_DESCRIPTOR_MASK 0x3
#define MMU_PTE_OUTPUT_ADDR_MASK 0xfffffffff000
#define MMU_PTE_DESCRIPTOR_INVALID 0x0
#define MMU_PTE_L012_DESCRIPTOR_BLOCK  0x1
#define MMU_PTE_L3_DESCRIPTOR_PAGE  0x3
#define MMU_PTE_ATTR_NON_SECURE  0x20
#define MMU_PTE_ATTR_ATTR_INDEX_MASK  0x1c
#define MMU_PTE_ATTR_STRONGLY_ORDERED  0x0
#define MMU_PTE_ATTR_DEVICE  0x4
#define MMU_PTE_ATTR_NORMAL_MEMORY  0x8
#define MMU_PTE_ATTR_AP_MASK  0xc0
#define MMU_PTE_ATTR_AP_P_RW_U_NA  0x0
#define MMU_PTE_ATTR_AP_P_RW_U_RW  0x40
#define MMU_PTE_ATTR_AP_P_RO_U_NA  0x80
#define MMU_PTE_ATTR_AP_P_RO_U_RO  0xc0
#define MMU_PTE_ATTR_PXN  0x60000000000000
#define MMU_PTE_ATTR_UXN  MMU_PTE_ATTR_PXN

//From lk kernel

#define ARM64_TLBI(op, val) \
({ \
	__asm__ volatile("tlbi " #op ", %0" :: "r" (val)); \
	ISB; \
})

#define ARM64_TLBI_NOADDR(op) \
({ \
	__asm__ volatile("tlbi " #op::); \
	ISB; \
})

#define ISB __asm__ volatile("isb" ::: "memory")
#define DSB __asm__ volatile("dsb sy" ::: "memory")


#define ARCH_ASPACE_FLAG_KERNEL (1U<<0)
#define MMU_KERNEL_PAGE_TABLE_ENTRIES_TOP 0x200
#define MMU_KERNEL_TOP_SHIFT 39
#define MMU_KERNEL_SIZE_SHIFT 48
#define MMU_KERNEL_PAGE_SIZE_SHIFT 0xC
#define MMU_PTE_L012_DESCRIPTOR_TABLE 0x3


#define MMU_USER_PAGE_TABLE_ENTRIES_TOP MMU_KERNEL_PAGE_TABLE_ENTRIES_TOP
#define MMU_USER_TOP_SHIFT MMU_KERNEL_TOP_SHIFT
#define MMU_USER_PAGE_SIZE_SHIFT MMU_KERNEL_PAGE_SIZE_SHIFT


#define PAGE_SIZE 0x1000
#define MB (1024UL*1024UL)


extern int printf(const char *restrict format, ...);
extern int fastboot_run(int *status,void (*callback)());
extern void fastboot_activity_cb();
extern int fastboot_stop;
extern char external_lib_avb_str[];
extern void *memmove(void *dest, const void *src, size_t n);
extern paddr_t paddr_to_kvaddr(vaddr_t vaddr);
