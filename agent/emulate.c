#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#define STACK_ADDRESS 		0xbffff000
#define PAGE_SIZE 		0x1000
#define ALIGN_PAGE_DOWN(x) (x & ~(PAGE_SIZE - 1))
#define ALIGN_PAGE_UP(x)  ((x + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define _ALIGN_UP(addr, size)	(((addr)+((size)-1))&(~((typeof(addr))(size)-1)))
#define _ALIGN(addr,size)     _ALIGN_UP(addr,size)
#define PAGE_ALIGN(addr)	_ALIGN(addr, PAGE_SIZE)
#define MAX_SEGMENTS 		10

typedef struct {
	uc_engine *uc;
	uint8_t* ptload_segments[MAX_SEGMENTS];
	unsigned long entry_point;
	uint8_t *stack;
	uint8_t *file;
} EmuCore;

/*prints emulator usage*/
void print_usage(const char *file_name) {
	printf("[*] Usage: %s <binary-to-emulate>\n", file_name);
	return;
}

/*maps file to memory*/
bool alloc_file(int *fd, struct stat *st, const char *filename, uint8_t **buf) { 
	if ((*fd = open(filename, O_RDWR)) < 0) {
       		return false;
   	}
               
  	if (fstat(*fd, st) < 0) {
       		return false;
   	}
                   
   	if ((*buf = mmap(NULL, st->st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
       		return false;
   	}   
   	return true;
}

/*parses and maps a given ELF image*/
bool parse_and_map_elf(const char *target_file, EmuCore *core) {
	int fd;
	struct stat st;
	uint8_t *buf;

	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;

	if (!alloc_file (&fd, &st, target_file, &buf)) {
		puts("[-] Cannot load file\n");
		return false;
	}  
	
	ehdr = (Elf32_Ehdr *)buf;
	phdr = (Elf32_Phdr *)&buf[ehdr->e_phoff];

	core->file = buf;
	core->entry_point = ehdr->e_entry;

	for (int i=0; i < ehdr->e_phnum; i++, phdr++) {
		if(phdr->p_type == PT_LOAD) {
			uint8_t *mem = (uint8_t *)calloc(1, PAGE_ALIGN(phdr->p_memsz));
			
			if (mem == NULL) {
				puts("[-] Error allocating segment");
				return false;
			}

	    		uc_mem_map_ptr(core->uc, phdr->p_vaddr, PAGE_ALIGN(phdr->p_memsz), UC_PROT_ALL, mem);
			if (!memcpy(mem, &buf[phdr->p_offset], phdr->p_filesz)) {
				printf("\t[-] Memory could not be copied at 0x%hhn\n", mem);
        			return false;
    			}
			core->ptload_segments[i] = mem;		
			printf("\t[*] Memory mapped at 0x%x\n", phdr->p_vaddr);
		}
	}
	return true;
}

/*maps memory in unicorn virtual environment*/
static void map_mem(EmuCore *core, uint32_t  address, uint32_t  size) {
	uint32_t  memStart = address;
	uint32_t  memEnd = address + size;
	uint32_t  memStartAligned = ALIGN_PAGE_DOWN(memStart);
	uint32_t  memEndAligned = ALIGN_PAGE_UP(memEnd);
	uc_mem_map(core->uc, memStartAligned, memEndAligned - memStartAligned, UC_PROT_ALL);
}

/*initializes stack and registers in unicorn virtual environment*/
bool setup_stack_and_registers(EmuCore *core) {
	int r_reg = 0;
	int r_esp = STACK_ADDRESS - (PAGE_SIZE * 2);
	
	uint32_t  stack_size = PAGE_SIZE * 2;
	uint32_t  stack_top = STACK_ADDRESS;
	uint32_t  stack_bottom = stack_top - stack_size;

	map_mem(core, stack_bottom, stack_size + 1);

	if (uc_reg_write(core->uc, UC_X86_REG_ESP, &stack_top) != UC_ERR_OK) {
		return false;
	}

	uc_reg_write(core->uc, UC_X86_REG_EAX, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_EBX, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_ECX, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_EDX, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_ESI, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_EDI, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_EBP, &r_reg);
	uc_reg_write(core->uc, UC_X86_REG_EIP, &core->entry_point);

	return true;
}

/*initializes unicorn instance*/
bool init_emu(EmuCore *core) {
	uc_err err;

    	err = uc_open(UC_ARCH_X86, UC_MODE_32, &core->uc);
 	if (err) {
        	printf("Failed on uc_open() with error returned: %u\n", err);
        	return false;
    	}
	return true;
}

/*hooks int instruction (i386, x86)*/
static void hook_interrupt(uc_engine *uc, void *user_data) {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    printf("[*] interrupt %x executing\n", eax);
	
    switch (eax) {
    	case 1: //exit
		break;
	case 4: //write
		break;
	case 0x5a: //mmap
    		uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    		uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
		uc_mem_read(uc, ebx, &ebx, sizeof(uint32_t));
		printf("\tebx: 0x%x, ecx: 0x%x\n", ebx, ecx);
		uc_mem_map(uc, ebx, ecx, UC_PROT_ALL);
    		uc_reg_write(uc, UC_X86_REG_EAX, &ebx);

		break;
	default:
		break;
    }
}

/*hooks syscall instruction (x86_64, x64)*/
static void hook_syscall(uc_engine *uc, void *user_data) {
    uint32_t eax;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);

    printf("[*] Syscall %x executing\n", eax);
}

/*hooks invalid accesses in unicorn environment virtual address space*/
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE_UNMAPPED:
		printf(">>> Missing memory is being WRITTEN at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 uc_mem_map(uc, address, 2 * 1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
                 return true;

        case UC_MEM_READ_UNMAPPED:
                 printf(">>> Missing memory is being READ at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
                 uc_mem_map(uc, address, 2 * 1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
                 return true;
    }
}

/*install unicorn hooks*/
void install_hooks(EmuCore *core) {
	uc_hook trace1, trace2, trace3;

	uc_hook_add(core->uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);
	uc_hook_add(core->uc, &trace2, UC_HOOK_INTR, hook_interrupt, NULL, 1, 0);
	uc_hook_add(core->uc, &trace3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);
}

int main (int argc, char ** argv) {
	EmuCore core;
	uc_err err;
	int uc_reg;

	if (argc != 2) {
		print_usage(argv[0]);
		return 1;
	}
	
	if (!init_emu(&core)) {
		return -1;
	}
	puts("[+] Emulator was initialized succesfully");

	if (!parse_and_map_elf(argv[1], &core)) {
		puts("[-] Failed to parse and map target ELF file");
		return -1;
	}
	puts("[+] Target ELF file was mapped sucessfully");

	if (!setup_stack_and_registers(&core)) {
		puts("[-] Failed to setup stack and registers");
		return -1;
	}
	puts("[+] Stack and registers setup correctly");
	
	install_hooks(&core);
	puts("[+] Hooks installed correctly");

	printf("[*] Starting execution at 0x%lx\n", core.entry_point);
	err = uc_emu_start(core.uc, core.entry_point, 4, 0, 0);
	if (err) {
        	printf("[-] Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
    	}
  
	uc_reg_read(core.uc, UC_X86_REG_EAX, &uc_reg);
    	printf(">>> EAX = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_EBX, &uc_reg);
    	printf(">>> EBX = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_ECX, &uc_reg);
    	printf(">>> ECX = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_EDX, &uc_reg);
    	printf(">>> EDX = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_ESI, &uc_reg);
    	printf(">>> ESI = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_EDI, &uc_reg);
    	printf(">>> EDI = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_EBP, &uc_reg);
    	printf(">>> EBP = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_ESP, &uc_reg);
    	printf(">>> ESP = 0x%x\n", uc_reg);
	uc_reg_read(core.uc, UC_X86_REG_EIP, &uc_reg);
    	printf(">>> EIP = 0x%x\n", uc_reg);

	return 0;
}

