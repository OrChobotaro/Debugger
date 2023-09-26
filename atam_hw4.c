#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */


int find_entry_sh(char *entry_to_find, int length, Elf64_Ehdr elf_header, int location_of_shstrtab_table, FILE *stream){
    Elf64_Shdr section_header_entry;
    char name_of_entry[length+1];

    for(int i = 0; i < elf_header.e_shnum; i++){
        int entry_offset = elf_header.e_shoff + (i * elf_header.e_shentsize);
        fseek(stream, entry_offset, SEEK_SET); // set pointer to start of section header table
        fread(&section_header_entry, sizeof (char), elf_header.e_shentsize, stream); // read entry to struct

        int offset_name = section_header_entry.sh_name; // offset from shstrtab
        fseek(stream, location_of_shstrtab_table + offset_name, SEEK_SET); // set pointer to location of name in shstrtab

        // read name
        fread(&name_of_entry, sizeof (char), length, stream);
        name_of_entry[length] = '\0';

        if(strcmp(name_of_entry, entry_to_find) == 0){
            return i;
        }

    }
    return -1;
}

int find_index_symbols(char* symbol_name, Elf64_Shdr section_header_symtab, FILE *stream, int strtab_location,
                       int symbols_found_index_entries[]){

    Elf64_Sym symtab_entry;
    int num_entries_symtab = section_header_symtab.sh_size/section_header_symtab.sh_entsize;
    int num_of_symbols_found = 0;
    int symtab_loctaion = section_header_symtab.sh_offset;

    for(int i = 0; i < num_entries_symtab; i++){
        // entry to struct
        fseek(stream, symtab_loctaion + (i * section_header_symtab.sh_entsize), SEEK_SET);
        fread(&symtab_entry, sizeof(char), section_header_symtab.sh_entsize, stream);

        // find name of symbol:

        // find length of name
        int name_offset_in_strtab = symtab_entry.st_name;
        fseek(stream, strtab_location + name_offset_in_strtab, SEEK_SET);
        int length = 0;
        char c[1];

        do {
            fread(&c, sizeof(char), 1, stream);
            length++;
        }
        while(strcmp(c, "\0") != 0);

        // find name
        char name[length];
        fseek(stream, strtab_location + name_offset_in_strtab, SEEK_SET);
        fread(&name, sizeof(char), length, stream);

        if(strcmp(name, symbol_name) == 0){
            symbols_found_index_entries[num_of_symbols_found] = i;
            num_of_symbols_found++;
        }

    }
    return num_of_symbols_found;
}


unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	// read elf file

    FILE * stream;
    stream = fopen(exe_file_name, "r");

    // elf headef
    Elf64_Ehdr elf_header;

    fread(&elf_header, sizeof(char), 64, stream);

    if(elf_header.e_type != ET_EXEC){
        *error_val = -3;
        return -1;
    }


    // section header
    Elf64_Shdr section_header_shstrtab;

    // offset of shstrtab from start of file
    int shstrtab_offset_in_sh = elf_header.e_shentsize * elf_header.e_shstrndx + elf_header.e_shoff;
    fseek(stream, shstrtab_offset_in_sh, SEEK_SET);
    fread(&section_header_shstrtab, sizeof(char), elf_header.e_shentsize, stream);

    // find shstrtab table
    int location_of_shstrtab_table = section_header_shstrtab.sh_offset;

    // find symtab anf strtab
    int symtab_index_sh = find_entry_sh(".symtab", 7, elf_header, location_of_shstrtab_table, stream);
    int strtab_index_sh = find_entry_sh(".strtab", 7, elf_header, location_of_shstrtab_table, stream);



    Elf64_Shdr section_header_strtab;
    Elf64_Shdr section_header_symtab;

    // write symtab to struct
    fseek(stream, elf_header.e_shoff + (symtab_index_sh * elf_header.e_shentsize), SEEK_SET);
    fread(&section_header_symtab, sizeof (char), elf_header.e_shentsize, stream);
    int symtab_loctaion = section_header_symtab.sh_offset;


    // write strtab to struct
    fseek(stream, elf_header.e_shoff + (strtab_index_sh * elf_header.e_shentsize), SEEK_SET);
    fread(&section_header_strtab, sizeof (char), elf_header.e_shentsize, stream);
    int strtab_location = section_header_strtab.sh_offset;



    // find symbol
    int num_entries_symtab = section_header_symtab.sh_size/section_header_symtab.sh_entsize;
    int symbols_found_index_entries[num_entries_symtab];
    int num_symbols = find_index_symbols(symbol_name, section_header_symtab, stream,
                                         strtab_location, symbols_found_index_entries);

    if(num_symbols == 0){
        *error_val = -1;
        return -1;
    }



    // iterate symbols
    Elf64_Sym sym_entry;
    // check if global
    for(int i = 0; i < num_symbols; i++){

        fseek(stream, symtab_loctaion + symbols_found_index_entries[i] * section_header_symtab.sh_entsize, SEEK_SET);
        fread(&sym_entry, sizeof (char), section_header_symtab.sh_entsize, stream);

        // if symbol is global:

        if((sym_entry.st_info >> 4) == 1){
            if(sym_entry.st_shndx == SHN_UNDEF){


                int index_rela_plt = find_entry_sh(".rela.plt", 9, elf_header, location_of_shstrtab_table, stream);


                Elf64_Shdr section_header_rela_plt;

                // write rela plt to struct
                fseek(stream, elf_header.e_shoff + (index_rela_plt * elf_header.e_shentsize), SEEK_SET);
                fread(&section_header_rela_plt, sizeof (char), elf_header.e_shentsize, stream);
                int rela_plt_location = section_header_rela_plt.sh_offset;

                int num_entries_rela_plt = section_header_symtab.sh_size/section_header_symtab.sh_entsize;


                int index_dynstr = find_entry_sh(".dynstr", 7, elf_header, location_of_shstrtab_table, stream);
                Elf64_Shdr section_header_dynstr;
                fseek(stream, elf_header.e_shoff + (index_dynstr * elf_header.e_shentsize), SEEK_SET);
                fread(&section_header_dynstr, sizeof (char), elf_header.e_shentsize, stream);
                int dynstr_location = section_header_dynstr.sh_offset;


                int index_dynsym = find_entry_sh(".dynsym", 7, elf_header, location_of_shstrtab_table, stream);



                Elf64_Shdr section_header_dynsym;

                // write rela plt to struct
                fseek(stream, elf_header.e_shoff + (index_dynsym * elf_header.e_shentsize), SEEK_SET);
                fread(&section_header_dynsym, sizeof (char), elf_header.e_shentsize, stream);
                int dynsym_location = section_header_dynsym.sh_offset;

                Elf64_Rela rela_entry;


                for (int i=0; i<num_entries_rela_plt; i++) {
                    fseek(stream, rela_plt_location + (i * section_header_rela_plt.sh_entsize), SEEK_SET);
                    fread(&rela_entry, sizeof(char), section_header_rela_plt.sh_entsize, stream);
                    unsigned int index_in_dynsym = ELF64_R_SYM(rela_entry.r_info);

                    Elf64_Sym dynsym_entry;
                    fseek(stream, dynsym_location + (index_in_dynsym * section_header_dynsym.sh_entsize), SEEK_SET);
                    fread(&dynsym_entry, sizeof(char), section_header_dynsym.sh_entsize, stream);


                    // find length of name
                    int name_offset_in_dynstr = dynsym_entry.st_name;
                    fseek(stream, dynstr_location + name_offset_in_dynstr, SEEK_SET);
                    int length = 0;
                    char c[1];

                    do {
                        fread(&c, sizeof(char), 1, stream);
                        length++;
                    }
                    while(strcmp(c, "\0") != 0);

                    // find name
                    char name[length];
                    fseek(stream, dynstr_location + name_offset_in_dynstr, SEEK_SET);
                    fread(&name, sizeof(char), length, stream);


                    if(strcmp(name, symbol_name) == 0){
                        *error_val = -4;
                        return rela_entry.r_offset;
                    }
                }
            }
            *error_val = 1;
            return sym_entry.st_value;
        }
    }

    *error_val = -2;
    return -1;
}


pid_t run_target(const char* programname) {
    pid_t pid;
    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execl(programname, programname, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}


void run_debugger(pid_t child_pid, unsigned long addr, int err) {
    int wait_status;
    struct user_regs_struct regs;
    int counter = 0;
    unsigned long return_addr;
    unsigned long old_addr = addr;
    long data_trap_start_func;
    long data_end_func;

    unsigned long rsp_address;


    //waiting for son after exec
    wait(&wait_status);

    if (err == -4) {
        addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    }

    long data_start_func = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);

    /* Write the trap instruction 'int 3' into the address */
    long data_trap = (data_start_func & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);


    while (1) {
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
            break;
        }
        counter++;


        /* See where the child is now */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);

        /* Remove the breakpoint by restoring the previous data */
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_start_func);
        regs.rip -= 1;

        rsp_address = regs.rsp + 8;

        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        /* Add breakPoint at the return address of the function */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        return_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
        data_end_func = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_addr, NULL);

        /* Write the trap instruction 'int 3' into the address */
        long data_trap_end_func = (data_end_func & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)return_addr, (void*)data_trap_end_func);


        /* Let the child run to the breakpoint and wait for it to reach it */
        while(1){

            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);

            /* See where the child is now */
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

            /* Remove the breakpoint by restoring the previous data */
            ptrace(PTRACE_POKETEXT, child_pid, (void*)return_addr, (void*)data_end_func);
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);


            if(rsp_address == regs.rsp){
                printf("PRF:: run #%d returned with %d\n", counter, (int)regs.rax);
                break;
            }

            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);

            ptrace(PTRACE_POKETEXT, child_pid, (void*)return_addr, (void*)data_trap_end_func);


        }


        /* Add breakPoint to the beginning of the function */
        if (err == -4  && counter == 1) {
            addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)old_addr, NULL);
            data_start_func = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
            data_trap_start_func = (data_start_func & 0xFFFFFFFFFFFFFF00) | 0xCC;

        }

        /* Write the trap instruction 'int 3' into the address */
        data_trap_start_func = (data_start_func & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap_start_func);

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    }

}



int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);
//    printf("%s is in address 0x%lx\n", argv[1], addr);

    if (err == -3) {
        printf("PRF:: %s not an executable!\n", argv[2]);
        return 0;
    }
    else if (err == -1) {
        printf("PRF:: %s not found! :(\n", argv[1]);
        return 0;
    }
    else if (err == -2) {
        printf("PRF:: %s is not a global symbol!\n", argv[1]);
        return 0;
    }
/*	else if (err >= 0) {
        ///////////////TO DELETE
        printf("%s will be loaded to 0x%lx\n", argv[1], addr);
    }*/
	else if (err == -4) {
/*        ///////////////TO DELETE
        printf("%s is a global symbol, but will come from a shared library\n", argv[1]);*/

    }


    pid_t child_pid;

    child_pid = run_target(argv[2]);

    run_debugger(child_pid, addr, err);


	return 0;
}


