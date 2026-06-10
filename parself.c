#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<inttypes.h>
#define FAIL "\x1b[2;91m" // Failure messages (USE ANSII ESCAPE CODES) syntax => "\x1b[1;COLOR_CODEm" the 1; => to apply contrast bold effect
#define SUCCESS1 "\x1b[2;92m"// success messages
#define WARNING "\x1b[2;93m"// warning agesmess

// total 16 bytes done till now()
void malloc_failed(FILE *fileptr){
	printf(FAIL "[x]malloc failed\n");
	printf(FAIL "exiting...\n");
	exit(0);
}

void fileread_failed(FILE *fileptr){
	fclose(fileptr);
	printf(FAIL "[x]File reading failed\n");
	printf(FAIL "exiting...");
	exit(0);
}

void elf_corrupt(FILE *fileptr){// function to display msg when elf binary file bytes are corrupted
	fclose(fileptr);
	printf(FAIL "[x]ELF file corrupted\n");
	exit(0);
}

uint64_t readbytes_and_shifting(unsigned char mag[], int offset, int size, int endi){// handles elf64 little and big endian 8 bytes shifiting
	uint64_t readBytes = 0x0;
	if(endi == 1){
		for(int i=0; i<size; offset++, i++)// handles little endian -> highest shfit applied to the size-1 offset value and lowest shift applied to offset value
			readBytes = readBytes | (uint64_t)mag[offset] << (i*8);
	}
	else{
		for(int i=size-1; i>=0; offset++, i--)// handles big endian -> highest shift applied to the offset value and lowest shift applied to size-1 offset value
			readBytes = readBytes | (uint64_t)mag[offset] << (i*8);
	}
	return readBytes;
}

void section_header_flags_display(unsigned char *shstrtab, uint64_t sh_name, uint64_t sh_type, uint64_t sh_flags, uint64_t sh_addr, uint64_t sh_offset, uint64_t sh_size, uint64_t sh_link, uint64_t sh_info, uint64_t sh_addralign, uint64_t sh_entsize){
	const char *section_name = (const char *)(shstrtab + sh_name); // shstrtab is the base address + sh_name(offset) so acts like arr[0] or arr[1] like arrays where in each offset/index information is stored. shstrtab is the Section Header String Table. Section names like .text, .data, .etc...
	printf(SUCCESS1 " %s\n", section_name);
	printf(SUCCESS1 "\tsh_name = %lu\n",sh_name);
	printf(SUCCESS1 "\tsh_type = %lu\n",sh_type);
	printf(SUCCESS1 "\tsh_flags = %lx\n",sh_flags);
	printf(SUCCESS1 "\tsh_addr = 0x%lx\n",sh_addr);
	printf(SUCCESS1 "\tsh_offset = %lu\n",sh_offset);
	printf(SUCCESS1 "\tsh_size = %lu\n",sh_size);
	printf("\n");
}

void section_header_flags(unsigned char *section_headers_data, unsigned char *shstrtab, int base, int endi, int elfclass, FILE *fileptr){
	uint64_t sh_name = 0x0, sh_type = 0x0, sh_flags = 0x0, sh_addr = 0x0, sh_offset = 0x0, sh_size = 0x0, sh_link = 0x0, sh_info = 0x0, sh_addralign = 0x0, sh_entsize = 0x0;
	/*
	| Field          | Offset | Size (Bytes) |
	| -------------- | ------ | ------------ |
	| `sh_name`      | 0      | 4            |
	| `sh_type`      | 4      | 4            |
	| `sh_flags`     | 8      | 4            |
	| `sh_addr`      | 12     | 4            |
	| `sh_offset`    | 16     | 4            |
	| `sh_size`      | 20     | 4            |
	| `sh_link`      | 24     | 4            |
	| `sh_info`      | 28     | 4            |
	| `sh_addralign` | 32     | 4            |
	| `sh_entsize`   | 36     | 4            |
	*/
	if(elfclass == 1){
		if(endi == 1){
			sh_name = readbytes_and_shifting(section_headers_data, base+0, 4, 1);
			sh_type = readbytes_and_shifting(section_headers_data, base+4, 4, 1);
			sh_flags = readbytes_and_shifting(section_headers_data,base+8, 4, 1);
			sh_addr = readbytes_and_shifting(section_headers_data, base+12, 4, 1);
			sh_offset = readbytes_and_shifting(section_headers_data, base+16, 4, 1);
			sh_size = readbytes_and_shifting(section_headers_data, base+20, 4, 1);
			sh_link = readbytes_and_shifting(section_headers_data, base+24, 4, 1);
			sh_info = readbytes_and_shifting(section_headers_data, base+28, 4, 1);
			sh_addralign = readbytes_and_shifting(section_headers_data, base+32, 4, 1);
			sh_entsize = readbytes_and_shifting(section_headers_data, base+36, 4, 1);
		}
		else{
			sh_name = readbytes_and_shifting(section_headers_data, base+0, 4, 2);
			sh_type = readbytes_and_shifting(section_headers_data, base+4, 4, 2);
			sh_flags = readbytes_and_shifting(section_headers_data, base+8, 4, 2);
			sh_addr = readbytes_and_shifting(section_headers_data, base+12, 4, 2);
			sh_offset = readbytes_and_shifting(section_headers_data, base+16, 4, 2);
			sh_size = readbytes_and_shifting(section_headers_data, base+20, 4, 2);
			sh_link = readbytes_and_shifting(section_headers_data, base+24, 4, 2);
			sh_info = readbytes_and_shifting(section_headers_data, base+28, 4, 2);
			sh_addralign = readbytes_and_shifting(section_headers_data, base+32, 4, 2);
			sh_entsize = readbytes_and_shifting(section_headers_data, base+36, 4, 2);
		}
	}
	else if(elfclass == 2){
		if(endi == 1){
			sh_name = readbytes_and_shifting(section_headers_data, base+0, 4, 1);
			sh_type = readbytes_and_shifting(section_headers_data, base+4, 4, 1);
			sh_flags = readbytes_and_shifting(section_headers_data, base+8, 8, 1);
			sh_addr = readbytes_and_shifting(section_headers_data, base+16, 8, 1);
			sh_offset = readbytes_and_shifting(section_headers_data, base+24, 8, 1);
			sh_size = readbytes_and_shifting(section_headers_data, base+32, 8, 1);
			sh_link = readbytes_and_shifting(section_headers_data, base+40, 4, 1);
			sh_info = readbytes_and_shifting(section_headers_data, base+44, 4, 1);
			sh_addralign = readbytes_and_shifting(section_headers_data, base+48, 8, 1);
			sh_entsize = readbytes_and_shifting(section_headers_data, base+56, 8, 1);
		}
		else{
			sh_name = readbytes_and_shifting(section_headers_data, base+0, 4, 2);
			sh_type = readbytes_and_shifting(section_headers_data, base+4, 4, 2);
			sh_flags = readbytes_and_shifting(section_headers_data, base+8, 8, 2);
			sh_addr = readbytes_and_shifting(section_headers_data, base+16, 8, 2);
			sh_offset = readbytes_and_shifting(section_headers_data, base+24, 8, 2);
			sh_size = readbytes_and_shifting(section_headers_data, base+32, 8, 2);
			sh_link = readbytes_and_shifting(section_headers_data, base+40, 4, 2);
			sh_info = readbytes_and_shifting(section_headers_data, base+44, 4, 2);
			sh_addralign = readbytes_and_shifting(section_headers_data, base+48, 8, 2);
			sh_entsize = readbytes_and_shifting(section_headers_data, base+56, 8, 2);
		}
	}
	else
		elf_corrupt(fileptr);
	section_header_flags_display(shstrtab ,sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize);
}

void section_header_info(unsigned char mag[], int endi, int elfclass, FILE *fileptr){
	/*
	elf32
	| Field         | Meaning                               | Offset | Size    |
	| ------------- | ------------------------------------- | ------ | ------- |
	| `e_shoff`     | Start of Section Header Table in file | 32     | 4 bytes |
	| `e_shentsize` | Size of one section header entry      | 46     | 2 bytes |
	| `e_shnum`     | Number of section header entries      | 48     | 2 bytes |
	| `e_shstrndx`  | Index of section-name string table    | 50     | 2 bytes |
	
	elf64
	| Field         | Meaning                               | Offset | Size    |
	| ------------- | ------------------------------------- | ------ | ------- |
	| `e_shoff`     | Start of Section Header Table in file | 40     | 8 bytes |
	| `e_shentsize` | Size of one section header entry      | 58     | 2 bytes |
	| `e_shnum`     | Number of section header entries      | 60     | 2 bytes |
	| `e_shstrndx`  | Index of section-name string table    | 62     | 2 bytes |
	*/
	uint32_t e_shoff32 = 0x0;
	uint64_t e_shoff64 = 0x0;
	uint16_t e_shentsize = 0x0, e_shnum = 0x0, e_shstrndx = 0x0;
	// elfclass = 1 => elf32
	// elfclass = 2 => elf64
	// endi = 1 => little
	// endi = 2 => big
	if(elfclass == 1){
		if(endi == 1){
			e_shoff32 = (uint32_t)readbytes_and_shifting(mag, 32, 4, 1);
			e_shentsize = (uint16_t)readbytes_and_shifting(mag, 46, 2, 1);
			e_shnum = (uint16_t)readbytes_and_shifting(mag, 48, 2, 1);
			e_shstrndx = (uint16_t)readbytes_and_shifting(mag, 50, 2, 1);
		}
		else{
			e_shoff32 = (uint32_t)readbytes_and_shifting(mag, 32, 4, 2);
			e_shentsize = (uint16_t)readbytes_and_shifting(mag, 46, 2, 2);
			e_shnum = (uint16_t)readbytes_and_shifting(mag, 48, 2, 2);
			e_shstrndx = (uint16_t)readbytes_and_shifting(mag, 50, 2, 2);
		}
	}
	else if(elfclass == 2){
		if(endi == 1){
			e_shoff64 = readbytes_and_shifting(mag, 40, 8, 1);
			e_shentsize = (uint16_t)readbytes_and_shifting(mag, 58, 2, 1);
			e_shnum = (uint16_t)readbytes_and_shifting(mag, 60, 2, 1);
			e_shstrndx = (uint16_t)readbytes_and_shifting(mag, 62, 2, 1);
		}
		else{
			e_shoff64 = readbytes_and_shifting(mag, 40, 8, 2);
			e_shentsize = (uint16_t)readbytes_and_shifting(mag, 58, 2, 2);
			e_shnum = (uint16_t)readbytes_and_shifting(mag, 60, 2, 2);
			e_shstrndx = (uint16_t)readbytes_and_shifting(mag, 62, 2, 2);
		}
	}
	else
		elf_corrupt(fileptr);
	if(elfclass == 1)
		printf(SUCCESS1 "\tStart of section headers: %u(bytes into file)\n",e_shoff32);
	else
		printf(SUCCESS1 "\tStart of section headers: %" PRIu64 " (bytes into file)\n", e_shoff64);
	printf(SUCCESS1 "\tSize of section headers: %u (bytes)\n",e_shentsize);
	printf(SUCCESS1 "\tNumber of section headers: %u\n",e_shnum);
	printf(SUCCESS1 "\tSection header string table Index: %u\n",e_shstrndx);
	size_t total_bytes = (size_t)e_shentsize * e_shnum;
	unsigned char *section_headers_data = malloc(total_bytes); // allocating total bytes present in section headers
	if(section_headers_data == NULL)
		malloc_failed(fileptr);
	long old_position = ftell(fileptr);// storing filepointer of program headers before going to section headers so that it can be restored later
	if(elfclass == 1)// bringing filepointer to the start of section header starting location
		fseek(fileptr, e_shoff32, SEEK_SET);
	else
		fseek(fileptr, e_shoff64, SEEK_SET);
	if(fread(section_headers_data, 1, total_bytes, fileptr) != total_bytes)// read all the data in all section headers
		fileread_failed(fileptr);
	uint64_t shstrndx_offset = 0x0, shstrndx_size = 0x0;
	int shstrndx_base = e_shstrndx * e_shentsize; // calculates the start of the .shstrtab section header entry inside your section_headers_data buffer.
	long old_position2 = ftell(fileptr); // storing filepointer before trying to access shstrndx location to read stuff
	if(elfclass == 1){// arranging shstrndx_offset and sizes based on the elf64 and elf32 binary file so that we can 
		shstrndx_offset = (uint32_t)readbytes_and_shifting(section_headers_data, shstrndx_base+16, 4, endi);
		shstrndx_size = (uint32_t)readbytes_and_shifting(section_headers_data, shstrndx_base+20, 4, endi);
	}
	else{
		shstrndx_offset = readbytes_and_shifting(section_headers_data, shstrndx_base+24, 4, endi);
		shstrndx_size = readbytes_and_shifting(section_headers_data, shstrndx_base+32, 4, endi);
	}
	unsigned char *shstrtab = malloc(shstrndx_size); // allocating size for shstrndx tab where .text, .data will be stored 
	if(shstrtab == NULL)
		malloc_failed(fileptr);
	fseek(fileptr, shstrndx_offset, SEEK_SET); // moving filepointer to the location of the shstrntab
	if(fread(shstrtab, 1, shstrndx_size, fileptr) != shstrndx_size)
		fileread_failed(fileptr);
	fseek(fileptr, old_position2, SEEK_SET); // previously filepointer set to shstrtab, now brought back to section headers
	printf(SUCCESS1 "\nSection Headers:\n");
	printf(SUCCESS1 "Segment Sections...\n");
	for(int i=0; i<e_shnum; i++){
		int base = i * e_shentsize; // calculate offset of each section header starting position
		printf("[%d]\t",i);
		section_header_flags(section_headers_data, shstrtab, base, endi, elfclass, fileptr);
		printf("\n");
	}
	free(section_headers_data);
	free(shstrtab);
	fseek(fileptr, old_position, SEEK_SET);// restoring file pointer to old positon so that program headers can be loaded during function tracebacks
}

void program_header_flags_display(uint64_t p_type, uint64_t p_flags, uint64_t p_offset, uint64_t p_vaddr, uint64_t p_filesz, uint64_t p_memsz, FILE *fileptr){
	const char *ptype = "UNKNOWN";
	switch(p_type){
	    case 0: ptype = "PT_NULL"; break;
	    case 1: ptype = "PT_LOAD"; break;
	    case 2: ptype = "PT_DYNAMIC"; break;
	    case 3: ptype = "PT_INTERP"; break;
	    case 4: ptype = "PT_NOTE"; break;
	    case 5: ptype = "PT_SHLIB"; break;
	    case 6: ptype = "PT_PHDR"; break;
	    case 7: ptype = "PT_TLS"; break;
	    /* GNU extensions */
	    case 0x6474e550: ptype = "GNU_EH_FRAME"; break;
	    case 0x6474e551: ptype = "GNU_STACK"; break;
	    case 0x6474e552: ptype = "GNU_RELRO"; break;
	    case 0x6474e553: ptype = "GNU_PROPERTY"; break;
	    /* Newer GCC/binutils */
	    case 0x6474e554: ptype = "GNU_SFRAME"; break;	    	
	}
	char r = (p_flags & 0x4) ? 'R' : '-';
	char w = (p_flags & 0x2) ? 'W' : '-';
	char x = (p_flags & 0x1) ? 'X' : '-';
	printf("\n");
	printf(SUCCESS1 "%-15s 0x%016" PRIx64 " 0x%016" PRIx64 "\n",
           ptype,
           p_offset,
           p_vaddr);
	if(p_type == 3){
		long old_position = ftell(fileptr);//ftell is used to find the current position of the filepointer [ftell returns long type so old_position is made long which is 64 bit value]
		char interp[p_filesz + 1]; // stories the dynamic linker path [so if we have to read 30 bytes for path, the extra +1 is to add null byte (null terminator)]
		interp[p_filesz] = '\0'; // null terminating
		fseek(fileptr, p_offset, SEEK_SET);// move filepointer to the start of the dynamic linker path location
		if(fread(&interp, 1, p_filesz, fileptr) != p_filesz){
			printf(FAIL "\n[x]Failed to read elf binary file\n");
			exit(0);
		}
		printf("\t[Requesting program interpreter: %s]\n",interp);
		fseek(fileptr, old_position, SEEK_SET);
	}

    printf(SUCCESS1 "%15s 0x%016" PRIx64 " 0x%016" PRIx64
           " %c%c%c\n",
           "",
           p_filesz,
           p_memsz,
           r,w,x);
}

void program_header_flags(unsigned char *program_header_data, int base, int endi, int elfclass, FILE *fileptr){
	/*
			| Field      | Offset | Size    | Description            |
			| ---------- | ------ | ------- | ---------------------- |
			| `p_type`   | 0      | 4 bytes | Segment type           |
			| `p_offset` | 4      | 4 bytes | Offset in file         |
			| `p_vaddr`  | 8      | 4 bytes | Virtual address        |
			| `p_filesz` | 16     | 4 bytes | Segment size in file   |
			| `p_memsz`  | 20     | 4 bytes | Segment size in memory |
			| `p_flags`  | 24     | 4 bytes | Permissions (R/W/X)    |

	*/
	uint64_t p_type, p_flags = 0x0, p_offset = 0x0, p_vaddr = 0x0, p_filesz = 0x0, p_memsz = 0x0;
	if(elfclass == 1){
		if(endi == 1){
			p_type = readbytes_and_shifting(program_header_data, base+0, 4, 1);
			p_offset = readbytes_and_shifting(program_header_data, base+4, 4, 1);
			p_vaddr = readbytes_and_shifting(program_header_data, base+8, 4, 1);
			p_filesz = readbytes_and_shifting(program_header_data, base+16, 4, 1);
			p_memsz = readbytes_and_shifting(program_header_data, base+20, 4, 1);
			p_flags = readbytes_and_shifting(program_header_data, base+24, 4, 1);	
		}
		else{
			p_type = readbytes_and_shifting(program_header_data, base+0, 4, 2);
			p_offset = readbytes_and_shifting(program_header_data, base+4, 4, 2);
			p_vaddr = readbytes_and_shifting(program_header_data, base+8, 4, 2);
			p_filesz = readbytes_and_shifting(program_header_data, base+16, 4, 2);
			p_memsz = readbytes_and_shifting(program_header_data, base+20, 4, 2);
			p_flags = readbytes_and_shifting(program_header_data, base+24, 4, 2);
		}
	}
	else if(elfclass == 2){
		/*
		| Field      | Offset | Size    |
		| ---------- | ------ | ------- |
		| `p_type`   | 0      | 4 bytes |
		| `p_flags`  | 4      | 4 bytes |
		| `p_offset` | 8      | 8 bytes |
		| `p_vaddr`  | 16     | 8 bytes |
		| `p_filesz` | 32     | 8 bytes |
		| `p_memsz`  | 40     | 8 bytes |

		*/
		if(endi == 1){
			p_type = readbytes_and_shifting(program_header_data, base+0, 4, 1);
			p_flags = readbytes_and_shifting(program_header_data, base+4, 4, 1);
			p_offset = readbytes_and_shifting(program_header_data, base+8, 8, 1);
			p_vaddr = readbytes_and_shifting(program_header_data, base+16, 8, 1);
			p_filesz = readbytes_and_shifting(program_header_data, base+32, 8, 1);
			p_memsz = readbytes_and_shifting(program_header_data, base+40, 8, 1);
		}
		else{
			p_type = readbytes_and_shifting(program_header_data, base+0, 4, 2);
			p_flags = readbytes_and_shifting(program_header_data, base+4, 4, 2);
			p_offset = readbytes_and_shifting(program_header_data, base+8, 8, 2);
			p_vaddr = readbytes_and_shifting(program_header_data, base+16, 8, 2);
			p_filesz = readbytes_and_shifting(program_header_data, base+32, 8, 2);
			p_memsz = readbytes_and_shifting(program_header_data, base+40, 8, 2);
		}
	}
	else
		elf_corrupt(fileptr);
	program_header_flags_display(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, fileptr);
}

void program_header_info(unsigned char mag[], int endi, int elfclass, FILE *fileptr){// function to display program header startinfo
	// elfclass = 1 => elf32
	// elfclass = 2 => elf64
	// endi = 1 => little
	// endi = 2 => big
	/*
	e_phoff     -> where Program Headers start
	e_phentsize -> size of one entry
	e_phnum     -> how many entries exist
	*/
	uint32_t e_phoff32 = 0x0;
	uint64_t e_phoff64 = 0x0;
	uint16_t e_phentsize = 0x0, e_phnum = 0x0;
	if(elfclass == 1){
		if(endi == 1){
			e_phoff32 = (uint32_t)readbytes_and_shifting(mag, 28, 4, 1);
			e_phentsize = (uint16_t)readbytes_and_shifting(mag, 42, 2, 1);
			e_phnum = (uint16_t)readbytes_and_shifting(mag, 44, 2, 1);
		}
		else{
			e_phoff32 = (uint32_t)readbytes_and_shifting(mag, 28, 4, 2);
			e_phentsize = (uint16_t)readbytes_and_shifting(mag, 42, 2, 2);
			e_phnum = (uint16_t)readbytes_and_shifting(mag, 44, 2, 2);
		}
	}
	else if(elfclass == 2){
		if(endi == 1){
			e_phoff64 = readbytes_and_shifting(mag, 32, 8, 1); 
			e_phentsize = (uint16_t)readbytes_and_shifting(mag, 54, 2, 1);
			e_phnum = (uint16_t)readbytes_and_shifting(mag, 56, 2, 1);
		}
		else{
			e_phoff64 = readbytes_and_shifting(mag, 32, 8, 2); 
			e_phentsize = (uint16_t)readbytes_and_shifting(mag, 54, 2, 2);
			e_phnum = (uint16_t)readbytes_and_shifting(mag, 56, 2, 2);
		}
	}
	else
		elf_corrupt(fileptr);
	if(elfclass == 1)
    		printf("\tStart of program headers: %u (bytes into file)\n", e_phoff32);
	else
    		printf(SUCCESS1 "\tStart of program headers: %" PRIu64 " (bytes into file)\n", e_phoff64);    
	printf(SUCCESS1 "\tSize of a program header: %u (bytes)\n", e_phentsize);
	printf(SUCCESS1 "\tNumber of program headers: %u\n", e_phnum);
	section_header_info(mag, endi, elfclass, fileptr);
	printf(SUCCESS1 "\nProgram Headers:\n");
	printf(SUCCESS1
	"%-15s %-18s %-18s\n",
	"Type",
	"Offset",
	"VirtAddr");

	printf(SUCCESS1
	"%15s %-18s %-18s %-5s\n",
	"",
	"FileSiz",
	"MemSiz",
	"Flags");
	if(elfclass == 1)
		fseek(fileptr, e_phoff32, SEEK_SET);// for elf32 binaries
	else
		fseek(fileptr, e_phoff64, SEEK_SET);// for elf64 binaries
	//unsigned char program_header_data[e_phentsize * e_phnum]; // total bytes reserved for program headers so that we can store info here
	size_t total_bytes = (size_t) e_phentsize * e_phnum;
	unsigned char *program_header_data = malloc(total_bytes);//must store the return value of malloc in a pointer variable, because you cannot assign a new memory address to an array name [this stores the total bytes present in program headers]
	if(program_header_data == NULL)
		malloc_failed(fileptr);
	if(fread(program_header_data, 1, total_bytes, fileptr) != total_bytes)// read the program headers info because program_header_data contains entire program headers data space. data stored in 1 byte chunks
		fileread_failed(fileptr);
	// there are multiple elf program headers in a file 
	// e_phentsize = <total size of one program headers>
	// e_phnum = <number of program headers>
	// so we need to iterate through all of these
	for(int i=0; i<e_phnum; i++){// iterate each program header and give info
		int base = i * e_phentsize;
		program_header_flags(program_header_data, base, endi, elfclass, fileptr);	
	}
	free(program_header_data);
}

void entry_point(unsigned char mag[], int endi, int elfclass, FILE *fileptr){ // check entry point address of elf binary byte[24-27] elf32 / byte[24-31] elf64
/*
e_ident      16 bytes
e_type        2 bytes
e_machine     2 bytes
e_version     4 bytes
e_entry       4 or 8 bytes

e_entry stores the program's entry point address.

The size of e_entry depends on the ELF class:
- ELF32 -> 4 bytes
- ELF64 -> 8 bytes

Since the address spans multiple bytes, we must reconstruct it into a
single integer value before using or comparing it.

For little-endian ELF files, the least significant byte (LSB) is stored
first in the file and the most significant byte (MSB) is stored last.
Therefore, we shift the higher-order bytes left by multiples of 8 bits
and combine them using bitwise OR (|) to rebuild the original address.

For big-endian ELF files, the most significant byte is stored first, so
the byte order is reconstructed in the opposite direction.

This is the same byte-reconstruction technique used earlier for e_type
and e_machine, but applied to a 4-byte (ELF32) or 8-byte (ELF64)
address value.
*/
	if(endi == 1 && elfclass == 1){// little endian elf32
		//uint32_t entry_addr = (uint32_t)mag[27] << 24 | (uint32_t)mag[26] << 16 | (uint32_t)mag[25] << 8 | (uint32_t)mag[24]; //24 - 27
		uint32_t entry_addr = (uint32_t)readbytes_and_shifting(mag, 24, 4, 1);
		printf("\tentry point address: 0x%x",entry_addr);
	}
	else if(endi == 1 && elfclass == 2){//little endian elf64
		//uint64_t entry_addr = (uint64_t)mag[31] << 56 | (uint64_t)mag[30] << 48 | (uint64_t)mag[29] << 40 | (uint64_t)mag[28] << 32 | (uint64_t)mag[27] << 24 | (uint64_t) mag[26] << 16 | (uint64_t)mag[25] << 8 | (uint64_t)mag[24];
		uint64_t entry_addr = readbytes_and_shifting(mag, 24, 8, 1);
		printf("\tentry point address: 0x%" PRIx64,entry_addr);
	}
	else if(endi == 2 && elfclass == 1){// big endian elf32
		//uint32_t entry_addr = (uint32_t)mag[24] << 24 | (uint32_t)mag[25] << 16 | (uint32_t)mag[26] << 8 | (uint32_t)mag[27];
		uint32_t entry_addr = (uint32_t)readbytes_and_shifting(mag, 24, 4, 2);
		printf("\tentry point address: 0x%x",entry_addr);
	}
	else if(endi == 2 && elfclass == 2){
		//uint64_t entry_addr = (uint64_t)mag[24] << 56 | (uint64_t)mag[25] << 48 | (uint64_t)mag[26] << 40 | (uint64_t)mag[27] << 32 | (uint64_t)mag[28] << 24 | (uint64_t) mag[29] << 16 | (uint64_t)mag[30] << 8 | (uint64_t)mag[31];
		uint64_t entry_addr = readbytes_and_shifting(mag, 24, 8, 2);
		printf("\tentry point address: 0x%" PRIx64 ,entry_addr);
	}
	else
		elf_corrupt(fileptr);
	printf("\n");
	program_header_info(mag, endi, elfclass, fileptr);
}

void elf_machineType_and_version(unsigned char mag[], int endi, int elfclass, FILE *fileptr){ // stores the e_machine byte[18-19] and byte [20 - 23] version
	// tells CPU architecture for which the elf binary was compiled
	/*
	| e_machine value | Architecture    |
	| --------------- | --------------- |
	| 0x003E          | x86-64          |
	| 0x0003          | x86             |
	| 0x00B7          | AArch64 (ARM64) |
	| 0x0028          | ARM             |
	| 0x0008          | MIPS            |
	*/
	uint16_t machine_type = 0;
	if(endi == 1)
		machine_type = (uint16_t)mag[19] << 8 | (uint16_t)mag[18];
	else
		machine_type = (uint16_t)mag[18] << 8 | (uint16_t)mag[19];
	if(machine_type == 0x003E)
		printf(SUCCESS1 "\tMachine: x86-64\n");
	else if(machine_type == 0x0003)
		printf(SUCCESS1 "\tMachine: x86\n");
	else if(machine_type == 0x00B7)
		printf(SUCCESS1 "\tMachine: AArch64 (ARM64)\n");
	else if(machine_type == 0x0028)
		printf(SUCCESS1 "\tMachine: ARM\n");
	else if(machine_type == 0x0008)
		printf(SUCCESS1 "\tMachine: MIPS\n");
	else
		elf_corrupt(fileptr);
	printf("\tVersion : 0x1\n");
	entry_point(mag, endi, elfclass, fileptr);
}

void elfType(unsigned char mag[], int endi, int elfclass, FILE *fileptr){ // find the elf type of the binary file consumes 2 bytes so endianness is essential to handle this
	// byte 9-15 was padding bytes
	// byte 16-17 offset
	/*
	0x0002 -> 20[0] 00[1] (little) so elf_type[0] = 00 elf_type[1] = 02
	0x0002 -> 00[0] 02[1] (big) so elf_type[0] = 00 elf_type[1] = 02

	byte order in little endian may change like 0x0002 can be arranged like 02[byte1] 00[byte2] value will be same but order different
	we are dealing with 2 bytes now so endianness matters very much IMP!!! this time.
	check the below logic to understand how to keep the data alignment ok before comparison
	*/
	uint16_t elf_type = 0;
	/*
	
	typecasting needs to uint16_t of mag[] needs be done since mag[] is unsigned char 
	lets consider the data is 0x1234
	and in little endian mag[16] = 0x34 and mag[17] = 0x12
	now when (uint16_t) mag[17] is done 0x12 becomes 00000000 00010010 (binary) and then <<8 makes it 00010010 00000000 which is basically 0x1200
	now when (uint16_t) mag[16] is done 0x34 becomes 00000000 00110100 (binary) and since no shifting<< so 
	0x1200 | 0x0034 is done
	which is 00010010 00000000
			 00000000 00110100
			 -----------------
				0x1234
			 -----------------
	*/
	if(endi == 1)
		elf_type = (uint16_t)mag[17] << 8 | (uint16_t)mag[16]; // handle little endianness
	else
		elf_type = (uint16_t)mag[16] << 8 | (uint16_t)mag[17]; // handle big endianness
	if(elf_type == 0x0000)
		printf(SUCCESS1 "\tType: ET_NONE\n");
	else if(elf_type == 0x0001)
		printf(SUCCESS1 "\tType: REL (Relocatable File)\n");
	else if(elf_type == 0x0002)
		printf(SUCCESS1 "\tType: EXEC (Executable File)\n");
	else if(elf_type == 0x0003)
		printf(SUCCESS1 "\tType: DYN (Shared Object File)\n");
	else if(elf_type == 0x0004)
		printf(SUCCESS1 "\tType: CORE (Core file)\n");
	else
		elf_corrupt(fileptr);
	elf_machineType_and_version(mag, endi, elfclass, fileptr);
}

void os_abis_version(unsigned char mag[],int endi,int elfclass, FILE *fileptr){// function to find os_abis, abis_version
	//byte 7 -15 is os, abi, abi_version
	// based on the value the abi follows that os abi rules
	// os_abis indicate what operating system abi rules does this particular abi follow. so if 0x3 = Linux then, the abi follows linux abi rules
	// if(mag[7] != 0x0 && mag[7] != 0x1 && mag[7] != 0x2 && mag[7] !=0x3 && mag[7] != 0x6 && mag[7] != 0x9)
	// 	elf_corrupt(fileptr);
	if(mag[7] == 0x0)
		printf(SUCCESS1 "\tOS/ABI: UNIX - SYSTEM V\n");
	else if(mag[7] == 0x1)
		printf(SUCCESS1 "\tOS/ABI: HP-UX\n");
	else if(mag[7] == 0x2)
		printf(SUCCESS1 "\tOS/ABI: NetBSD\n");
	else if(mag[7] == 0x3)
		printf(SUCCESS1 "\tOS/ABI: Linux\n");
	else if(mag[7] == 0x6)
		printf(SUCCESS1 "\tOS/ABI: Solaris\n");
	else if(mag[7] == 0x9)
		printf(SUCCESS1 "\tOS/ABI: FreeBSD\n");
	else
		elf_corrupt(fileptr);
	printf(SUCCESS1 "\tABI Version: %d\n",mag[8]);// abi version
	elfType(mag, endi, elfclass, fileptr);
}

void arch_endian_version(unsigned char mag[], FILE *fileptr){ // check architecture, endiannes, version
	int endi = 1;
	int elfclass = 1;
	if((mag[4] != 0x1 && mag[4] != 0x2) || (mag[5] != 0x1 && mag[5] != 0x2) || (mag[6] != 0x1))
		elf_corrupt(fileptr);
	if(mag[4] == 0x1)// architecture(class) 0x1 = 32bit 0x2 = 64bit
		printf(SUCCESS1 "\tClass: ELF32\n");
	else{
		printf(SUCCESS1 "\tClass: ELF64\n");
		elfclass = 2;
	}
	if(mag[5] == 0x1)// data 0x1 = little 0x2 = big
		printf(SUCCESS1 "\tData: little endian\n");
	else{
		printf(SUCCESS1 "\tData: big endian\n"); // mag[6]
		endi = 2;
	}
	printf(SUCCESS1 "\tVersion: 0x1\n");
	os_abis_version(mag, endi, elfclass, fileptr);
}

void elfHeader(char *filename){// here program accepts only 1 string and char * means the pointer starts from the first character of the string until it hits null terminator
	FILE *fileptr;
	fileptr = fopen(filename, "rb"); // reading binary file
	if(fileptr == NULL){
		perror(FAIL "[-]file open failed.\n");
		exit(0);
	}
	unsigned char mag[64];
	if(fread(&mag, 1, sizeof(mag), fileptr) != sizeof(mag)){
		printf(FAIL "\n[x]Failed to read elf binary file\n");
		exit(0);
	} 
	// [7F 45 4C 46] magic bytes of an elf binary
	unsigned char magic_bytes[] = {0x7f, 0x45, 0x4c, 0x46}; // unsigned to avoid sign bit interpretations
	/*
	so raw byte is in 0s and 1s
	compiler sees hex values as 0s and 1s
	so it basically compares 2 binary values and gives the result
	*/
	for(int i=0; i<4; i++){
		if(mag[i] != magic_bytes[i]){
			printf(FAIL "[x]Not ELF Binary\n");
			fclose(fileptr);
			exit(0);
		}
	}
	printf(SUCCESS1 "[*]ELF Binary\n");
	printf(SUCCESS1 "ELF Header :\n");
	arch_endian_version(mag, fileptr);
	fclose(fileptr);
	return;
}

int main(int argc, char *argv[]){
	// c doesnt have a string variable
	// so we use (char *) to point to the first character of the string in memory
	// [] used to store multiple arguments. Without [] if there is any space for like different args so it will only store the first arg until space encountered
	if(argc < 2 || argc > 2){
		printf(WARNING "[-]incorrect/missing arguments\n");
		exit(0);
	}
	elfHeader(argv[1]);
	// isStatic_Dynamic_Linked(argv[1]);
	return 0;
}
