#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h>
#include "encoding.h"
#define ELF_MAGIC 0x464c457f
#define ELF_PT_LOAD 1
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
#define EI_NIDENT 16
uint32_t LoadELFFromFile(const char *);
/*
void store_tag(void *addr, int tag) {
  unsigned int temp;
  asm volatile ("tagw %0, %0; andi %0, %0, 0; amoor.w %0, %0, 0(%1)"
                :
                :"r"(tag), "r"(addr) 
                );
  
}
*/

void store_tag(void *addr, int tag) {
  unsigned int temp;
  asm volatile ("lwu %2,0(%1);tagw %2, %0; sw %2,  0(%1);fence.i;andi %0, %0, 0"
                :
                :"r"(tag), "r"(addr) ,"r"(temp)
                );
  
}


typedef struct {
    unsigned char e_ident[EI_NIDENT];  // 最开头是16个字节的e_ident, 其中包含用以表示ELF文件的字符，以及其他一些与机器无关的信息。开头的4个字节值固定不变，为0x7f和ELF三个字符。
    uint16_t      e_type;  // 该文件的类型 2字节
    uint16_t      e_machine;  // 该程序需要的体系架构 2字节
    uint32_t      e_version;  // 文件的版本 4字节
    Elf64_Addr   e_entry;  // 程序的入口地址 8字节
    Elf64_Off      e_phoff;  // Program header table 在文件中的偏移量 8字节
    Elf64_Off      e_shoff;  // Section header table 在文件中的偏移量 8字节
    uint32_t      e_flags;  // 对IA32而言，此项为0。 4字节
    uint16_t      e_ehsize;  // 表示ELF header大小 2字节
    uint16_t      e_phentsize;  // 表示Program header table中每一个条目的大小 2字节
    uint16_t      e_phnum;  // 表示Program header table中有多少个条目 2字节
    uint16_t      e_shentsize;  // 表示Section header table中的每一个条目的大小 2字节
    uint16_t      e_shnum;  // 表示Section header table中有多少个条目 2字节
    uint16_t      e_shstrndx;  // 包含节名称的字符串是第几个节 2字节
} Elf64_Ehdr;
typedef struct {
    uint32_t   p_type;  // 当前Program header所描述的段的类型
    uint32_t   p_flags;  // 与段相关的标志
    Elf64_Off  p_offset;  // 段的第一个字节在文件中的偏移
    Elf64_Addr p_vaddr;  // 段的第一个字节在内存中的虚拟地址
    Elf64_Addr p_paddr;  // 在物理内存定位相关的系统中，此项是为物理地址保留
    uint64_t   p_filesz;  // 段在文件中的长度
    uint64_t   p_memsz;  // 段在内存中的长度
    uint64_t   p_align;  // 根据此项值来确定段在文件及内存中如何对齐
} Elf64_Phdr;
typedef struct elf64_shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;


// return value: the return address offset text 
// filename: the filename want to tag
uint32_t LoadELFFromFile(const char *filename)
{
    int fd, i;
    Elf64_Ehdr  eh;
    Elf64_Shdr esh;

    if ((fd = open(filename, O_RDONLY)) <= 0) {
	printf("Could not find '%s'\n", filename);
	return -1;
    }

    // Read ELF header
    read(fd, &eh, sizeof(Elf64_Ehdr ));
  
    struct stat st;
    if (stat(filename, &st) != 0) {
        perror("stat");
        return 1;
    }
    char *p = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    Elf64_Shdr *shdr = (Elf64_Shdr *)(p + eh.e_shoff);
    Elf64_Shdr *sh_strtab = &shdr[eh.e_shstrndx];
    const char *const sh_strtab_p = p + sh_strtab->sh_offset;
    printf("eh.shnum %d\n", eh.e_shnum);
    
    //uint32_t tag_addr=0x119c0;  
    //uint32_t tagit;
    uint64_t sh_offset;
    for (i = 0; i < eh.e_shnum; i++) {
            
        // Seek to program header
        lseek(fd, eh.e_shoff + (i * sizeof(Elf64_Shdr)), SEEK_SET);
        // Load program header
        read(fd, &esh, sizeof(Elf64_Shdr));
        // Seek to section
        lseek(fd, esh.sh_offset, SEEK_SET);
        // Load section      
        int stringsection = eh.e_shstrndx;
                
        if(!strcmp(sh_strtab_p + shdr[i].sh_name,".text")){
            
            Elf64_Shdr *sh_text = &shdr[i];
            uint32_t sh_flag = *(uint32_t*)( (unsigned long int)sh_text+sizeof(uint32_t)+sizeof(uint32_t));
            uint64_t sh_addr = *(uint64_t*)( (unsigned long int)sh_text+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint64_t));
            sh_offset = *(uint64_t*)( (unsigned long int)sh_text+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint64_t)+sizeof(uint64_t));
            printf("text section %s %s sh_flag %x sh_addr %lx\n",sh_strtab_p + shdr[i].sh_name,sh_strtab_p + shdr[i].sh_name,sh_flag,sh_addr);
            //tag
            //uint32_t sh_offset_base = *(uint64_t*)((uint64_t)p+sh_offset);
            //tagit = (uint64_t)tag_addr-(uint64_t)sh_addr;
            //uint32_t taginstr = *(uint64_t*)((uint64_t)p+sh_offset+tagit);

            //printf("sh_offset %lx sh_offset_base %lx\n",sh_offset,*(uint64_t*)((uint64_t)p+sh_offset));
            //printf("tag %lx %lx\n",taginstr,tagit);
                  
        }
    }

    close(fd);
    printf("end\n");
    return sh_offset;//+tagit;
    
}


static int readfileline(const char *txtname){

    FILE * fp;
    int lines=0;
    int ch=0;
    fp = fopen(txtname, "r");
    
    if(fp == NULL){
        printf("file open failed.\n");
        exit(1);
    }
    
    int j=0;
    char a[100];
    //fseek(fp,0,SEEK_SET);
    while((ch = fgetc(fp)) != EOF){
        if(ch == '\n'){
            lines++;
            
        }
    }
    
    printf("\n\nlines: %d.\n", lines);

    fclose(fp);
    
    return lines;
}

static void readfilecontent(const char *txtname,int tagarray[][2]){

    FILE * fp;
    fp = fopen(txtname, "r");

    if(fp == NULL){
        printf("file open failed.\n");
        exit(1);
    }
    
    char cLine[200];
    int j=0;
    char * pch;
    fseek(fp,0,SEEK_SET);
    while(1){
	fgets(cLine,200,fp);
	if(!feof(fp)){
	    //printf("cline %s\n",cLine);
	    tagarray[j][0] = atoi(strtok(cLine, " "));  
	    tagarray[j][1] = atoi(strtok(NULL, " "));
	    //printf("tagarray %d   %d\n",tagarray[j][0],tagarray[j][1]);
	    j++;
	    
	}
	else{
	    break;
	}
    }
    
    fclose(fp);  
    
}


static void tagging(const char *txtname,char* pointer){
    
    uint64_t tag_mask =TMASK_STORE_PROP|TMASK_LOAD_PROP;
    write_csr(utagctrl , tag_mask);    

    int fileline=readfileline(txtname);
    int (*tagarray)[2]=(int(*)[2])malloc(sizeof(int)*fileline*2);
    
    readfilecontent(txtname,tagarray);  
    printf("file lines: %d.\n", fileline);
    
    
    //printf("readbuff %lx\n",*bufftest);
    //lseek(fd2,return_instaddr,SEEK_SET);    
    //printf("readbuff %lx\n",*(uint32_t*)bufftest);
    
    //write(fd2,bufftest,4); 
       
    for(int i=0;i<fileline;i++){
        //printf("hi\n");
    	uint32_t p = tagarray[i][0];
    	int val = tagarray[i][1];
    	//printf("INT %x %d\n",p,val);
    	store_tag((uint32_t*)(p+pointer),val);//jidehaiyoushangmmian utal
    	
    	
    	printf("pointer+p %x ",*(uint32_t*)(pointer+p));
    	//debug:change the instruction
    	//*(uint32_t*)(pointer+p)=0x793;
    }
    
    free(tagarray);
    tagarray=NULL;
    
}


/*
  1. open the origin file want to tag and the file with tag
  2. copy all the file
  3. get the sh_offset
  4. mmap the file want to tag
  5. tagging
  6. close the file

*/
int main(int argc,char *argv[])
{ 
    
    FILE *fp1; 
    FILE *fp2; 
    //the origin file want to tag
    fp1=fopen(argv[1],"r"); 
    //the file with tag
    fp2=fopen(argv[2],"w+"); 
    char buff[1024];
    int len;
    
    //copy the file
    while(len = fread(buff,1,sizeof(buff),fp1)){
        fwrite(buff,1,len,fp2);
    }
    fclose(fp1); 
    fclose(fp2); 
    
    //get the sh_offset
    uint32_t return_instaddr=0;
    return_instaddr=LoadELFFromFile(argv[2]);
    printf("return_instaddr %x\n",return_instaddr);
    struct stat st;
    if (stat(argv[2], &st) != 0) {
        perror("stat");
        return 1;
    }
    
    //mmap the file want to tag
    int fd2;
    fd2 = open(argv[2],O_RDWR,00777);
    char *p = mmap(0, st.st_size, PROT_WRITE|PROT_READ, MAP_SHARED , fd2, 0);
    uint64_t* pointer=(uint64_t*)(p+return_instaddr);
    printf("main pointer %x *p %x p %s return %x value %x\n",pointer,*p,p,return_instaddr,*(uint64_t*)pointer);
    //tagging
    tagging(argv[3],pointer);
    
    close(fd2);
    int msync_fd =  msync( p, st.st_size,  MS_SYNC);
    if(msync_fd == -1){
        perror("msync\n");
        return 0;
    }
    else{
        printf("sync\n");
    }
    munmap(p,st.st_size);

    return 0;
} 



