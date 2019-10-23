#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <syscall.h>
#include <elf.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>
#include <spawn.h>
#include <sys/wait.h>

#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_RESET "\033[0m"

#define SEND_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN (NLMSG_LENGTH(sizeof(struct cn_msg) + \
				       sizeof(struct proc_event)))
#define SEND_MESSAGE_SIZE    (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE    (NLMSG_SPACE(RECV_MESSAGE_LEN))
#define max(x,y) ((y)<(x)?(x):(y))
#define min(x,y) ((y)>(x)?(x):(y))
#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))
#define PROC_CN_MCAST_LISTEN (1)
#define PROC_CN_MCAST_IGNORE (2)
#define ElfW(type)	_ElfW (Elf, __WORDSIZE, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t

#if __WORDSIZE == 64
#define SYS_EXITGROUP 231
#define SYS_EXIT 60
#define SYS_PTRACE 101
#define SYS_GETPID  39
#define OREG(reg) reg.orig_rax
#define REG(reg) reg.rax
#else
#define SYS_EXITGROUP 252
#define SYS_EXIT 1
#define SYS_PTRACE 26
#define SYS_GETPID 20
#define OREG(reg) reg.orig_eax
#define REG(reg) reg.eax
#endif

static int g_Pid;

/*Fixes elf image for gene-extraction to be possible*/
void fix_elf(FILE **fd, unsigned long delta) {
	size_t file_size;
	char *buff;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Dyn) *dyn;

	printf("[*] Fixing ELF header\n");
	fseek(*fd, 0L, SEEK_END);
	file_size = ftell(*fd);       

	buff = calloc(sizeof(char), file_size);

	fseek(*fd, 0, SEEK_SET);
	fread(buff, sizeof(char), file_size, *fd);
	ehdr = (ElfW(Ehdr*))buff;

	ehdr->e_shnum = 0;
	ehdr->e_shoff = 0;
	ehdr->e_shstrndx = 0;

	phdr = (ElfW(Phdr*))&buff[ehdr->e_phoff];

	for (int i=0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_DYNAMIC) {
			printf("[*] Fixing dynamic segment\n");
			dyn = (ElfW(Dyn*))&buff[phdr->p_offset];
			while(dyn->d_tag != DT_NULL) {
				if (dyn->d_tag == DT_SYMTAB ||
						dyn->d_tag == DT_STRTAB || 
						dyn->d_tag == DT_RELA || 
						dyn->d_tag == DT_VERSYM ||
						dyn->d_tag == DT_PLTGOT ||
						dyn->d_tag == DT_JMPREL ||
						dyn->d_tag == DT_GNU_HASH) {
					dyn->d_un.d_ptr &= ~0xfffff000;
				}
				dyn++;
			}	
		}
	}
	fseek(*fd, 0, SEEK_SET);
	fwrite(buff, sizeof(char), file_size, *fd);
	free(buff);
	printf(COLOR_GREEN"[+] ELF image sucessfully dumped"COLOR_RESET"\n");
}

/*process_vm_readv syscall wrapper function*/
char * read_mem_readv(unsigned long start_address, long length, int pid) {
	struct iovec local[1];
	struct iovec remote[1];
	
	local[0].iov_base = calloc(sizeof(char), length);
	local[0].iov_len = length;

	remote[0].iov_base = (void*)start_address;
    	remote[0].iov_len = length;

	long unsigned int nread = process_vm_readv(pid, local, 2, remote, 1, 0);
	if (nread != length) {
		printf("[!] Error reading memory at 0x%lx, %lx\n", start_address, nread);
		return NULL;
	}
	return local[0].iov_base;
}  

/*dumps process memory and writes it to a specific file offset*/
int dump_memory_to_file(unsigned long start_address, long length, int pid, FILE **fd, unsigned long mapping_offset) {
	char *buff;
	buff = read_mem_readv(start_address, length, pid);
	if (buff == NULL) {
		printf("[!] Error at dumping memory at 0x%lx, %lx\n", start_address, length);
		return -1 ;
	}
	fseek(*fd, mapping_offset, SEEK_SET);
	fwrite(buff, sizeof(char), length, *fd);
	fseek(*fd, 0, SEEK_SET);
	free(buff);
	return 0;
}

/*dumps a specific elf image at a given virtual address*/
int dump_elf(long long start_address, long length, int pid, FILE **fd, unsigned long mapping_offset) {
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	char *elf_image;
	uint64_t delta;

	elf_image = read_mem_readv(start_address, length, pid);
	if (elf_image == NULL ) {
		printf(COLOR_RED"[-] Error dumping ELF image"COLOR_RESET"\n");
		return -1;
	}
	ehdr = (ElfW(Ehdr*))elf_image;
	phdr = (ElfW(Phdr*))&elf_image[ehdr->e_phoff];
	delta = (ehdr->e_type == ET_DYN) ? start_address : 0;
	
	for (int i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) {
			if (dump_memory_to_file(delta + phdr->p_vaddr, phdr->p_filesz,
					pid,
					fd,
					phdr->p_offset) == -1) {
				printf(COLOR_RED"[-] Error dumping ELF image"COLOR_RESET"\n");
				return -1;
			}
		}
	}
	fix_elf(fd, delta);
	return 0;
}

/*prints agent's binaries usage*/
void print_usage(const char *program_name) {
	printf("[*] Usage: sudo %s <process to execute> [<timeout>]\n", program_name);
	return;
}

/*dumps all existant elf images which are not dynamically linked libraries*/
bool dump_memory_artifacts(int pid) {
	char pMapsFilename[1024];
	char pCommFilename[1024];
	char pOutFilename[1024];
	char pFilename[1024];
	char *pDumpedFileName;
	char pLine[256];
	FILE* pMapsFile;
	FILE* pCommFile;
	FILE* pOutFile;
	int dump_count;
	uint32_t *magic;

	sprintf(pMapsFilename, "/proc/%d/maps", pid);
	sprintf(pCommFilename, "/proc/%d/comm", pid);
	pMapsFile = fopen(pMapsFilename, "r");
	pCommFile = fopen(pCommFilename, "r");

	if (pMapsFile < 0) {
		printf("[-] %s could not be opened\n", pMapsFilename);
		return false;
	}

	if (pCommFile < 0) {
		printf("[-] %s could not be opened\n", pCommFilename);
		return false;
	}

	fgets(pFilename, sizeof(pFilename), pCommFile);

	while (fgets(pLine, sizeof(pLine), pMapsFile) != NULL) {
	    unsigned long start_address;
	    unsigned long end_address;
	    unsigned long mapping_offset;
	    char readFlag;
	    void *centinel;
	    
	    if (!strstr(pLine, ".so") && !strstr(pLine, "[vdso]") && !strstr(pLine, "[vsyscall]")) {  
		sscanf(pLine, "%lx-%lx %c%*c%*c%*c %lx\n", 
				&start_address, 
				&end_address,
				&readFlag,
				&mapping_offset);
		
		magic = (uint32_t*)read_mem_readv(start_address, 4, pid); // implement better heuristics to identify ELFs in memory. Probs based on Elf*_Phdr regex
		if (readFlag == 'r' && magic != NULL && magic[0] == 0x464c457f) {
			pDumpedFileName = (uint8_t*)calloc(sizeof(char), strlen("dumped") + 3);

			sprintf(pDumpedFileName, "%s-%.2d", "dumped", dump_count);
			printf("[+] Attempting to dump ELF image at 0x%lx\n", start_address);
			
			pOutFile = fopen(pDumpedFileName, "wb+");
			if (dump_elf(start_address, end_address - start_address, pid, &pOutFile, mapping_offset) == -1) {
				fclose(pOutFile);
				remove(pDumpedFileName);
				continue;
			}
			dump_count++;
			fclose(pOutFile);
			
		}
	    }
	}
	fclose(pMapsFile);
	fclose(pCommFile);
	return true;
}

/*function to be executed on SIGALRM signal*/
void handle_alarm(int sig) {
	dump_memory_artifacts(g_Pid);
	kill(0, SIGQUIT);
	exit(0);
}

int handle_file(char *target_process_name, char **environ, int timeout) {
    pid_t pid;
    int status;
    char *argv[] = {target_process_name, NULL}; 

    status = posix_spawn(&pid, target_process_name, NULL, NULL, argv, environ);
    if (status == 0) {
	if (timeout) {
		g_Pid = pid;
		signal(SIGALRM, handle_alarm);
		alarm(timeout);
	}
    
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	while(waitpid(pid, &status, 0) && ! WIFEXITED(status)) {
		struct user_regs_struct regs; 
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (OREG(regs) == SYS_EXITGROUP || OREG(regs) == SYS_EXIT) {
			dump_memory_artifacts(pid);
		} else if (OREG(regs) == SYS_PTRACE) { // replacing ptrace syscall
			OREG(regs) = SYS_GETPID;
			REG(regs) = SYS_GETPID;
			ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		}
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
	ptrace(PTRACE_DETACH, pid, NULL, NULL);

    } else {
        printf("posix_spawn: %s\n", strerror(status));
    }
}
int main(int argc, char ** argv, char **envp) {
	if (geteuid() != 0 || argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	return handle_file(argv[1], envp, argc == 3 ? atoi(argv[2]) : 0 );
}

