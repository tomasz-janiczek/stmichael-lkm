/* Saint Michael, Linux Kernel Module.
 * Verions: 0.11
 *
 * August 6, 2002
 *
 *
 *    Copyright (C) 2001  Timothy Lalwess (lawless@netdoor.com)
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License as
 *    published by the Free Software Foundation; either version 2 of
 *    the License, or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be
 *    useful, but WITHOUT ANY WARRANTY; without even the implied
 *    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *    PURPOSE.  See the GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public
 *    License along with this program; if not, write to the Free
 *    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *    USA.
 *      
 *
 * 
 */


#include <linux/sys.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/segment.h>
#include <asm/unistd.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <sys/syscall.h>
#include <asm/errno.h>
#include <linux/interrupt.h>  
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <linux/mman.h>
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"

mm_segment_t old_fs;

char sm_message_label[] = "(STMICHAEL):";

char *sm_message_strings[] = {
        "Failed to Initilize.\n",
	"Evasion of Filesystem Checks Detected.\n",
	"Covert Kernel Module Detected. Revealed.\n",
	"Kernel Structures Modified. Attempting to Restore.\n",
	"Kernel Structures Modified. Unable to Restore.\n",
	"Possible LKM Rootkit Detected.\n",
	"Rebooting.\n",
        "Catastrophic LKM Rootkit Activity Detected. Kernel directly Modified.\n",
        "The Kernel has been Reloaded.\n",
        "Unable to Recover from the Catastrophic Modification. Rebooting.\n",
	"Modifications to The Filesystem Structures Have Been Made.\n",
        ""
        };


void sjp_l_munge_memory ( void )
{
  int i;

  
  // Fist message strings.
  sjp_l_crypt_string(sm_message_label);
  for (i = 0; sm_message_strings[i][0] != '\0'; i++)
      sjp_l_crypt_string( sm_message_strings[i] );
}


char * sjp_l_decrypt_string ( char *p  )
{
  return sjp_l_decrypt_data(p, 0);
}

char null_string[1] = "";

char * sjp_l_decrypt_data ( char *p, long len )
{

  unsigned long k;
  unsigned long i;

  k = (char) (KEY % 256); 

  if (len < 0)
    return null_string;

  for (i = 0;i < ( len ? len : 100)  ;i++)
  {
     //p[i];  
     p[i] ^= k; 
     k += i; k &= 0x000000FF;
     if (p[i] == '\0' && len == 0 )
           break; 
  }   
  
  return p;
}

void* sjp_l_memset(void* mem,unsigned char value,unsigned int s)
{
    register unsigned int i;
    
    if(!mem || !s) return NULL;
    for(i = 0;i < s;i++) ((unsigned char*)mem)[i] = value;
    return mem;
}

void* sjp_l_memcpy(void* dst,const void* src,unsigned int s)
{
    register unsigned int i;
    
    if(!src || !dst || !s) return NULL;
    for(i = 0;i < s;i++) ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
    return dst;
}

int sjp_l_memcmp(const void* s1,const void* s2,unsigned int s)
{
    register unsigned int i;
    
    if(!s1 || !s2 || !s) return 1;
    for(i = 0;i < s;i++) {
	if(((unsigned char*)s1)[i] != ((unsigned char*)s2)[i]) return 1;
    }
    return 0;
}

char* sjp_l_strncpy(char* dst,const char* src,unsigned int s)
{
    register unsigned int i;
    
    if(!dst || !src || !s ) return NULL;
    sjp_l_memset(dst,0,s);
    for(i = 0;i < s;i++) {
	if(src[i] == '\0') break;
	dst[i] = src[i];
    }
    return dst;
}

inline int sjp_l_strnlen(const char* s1,int max_len)
{
    register int i;

    for (i = 0; i < max_len && s1[i]; i++);
    return i;
}

int sjp_l_strlen(const char* s1)
{
    register unsigned int i;

    if(!s1) return 0;
    for(i = 0;s1[i];i++);
    return i;
}

inline int sjp_l_strncmp(const char* s1,const char* s2,int max_len)
{
    register int i;

    for (i = 0; i < max_len && ( s1[i] != '\0' && s2[i] != '\0') ; i++)
	if (s1[i] != s2[i])
	    return 1;
    return 0;
}

int sjp_l_strcmp(const unsigned char* s1,const unsigned char* s2)
{
    register unsigned int i;

    if(!s1 || !s2) return 1;
    for(i = 0;(s1[i] != '\0' && s2[i] != '\0');i++) {
	if(s1[i] != s2[i]) return 1;
    }
    return 0;
}

char* sjp_l_substr(char* s,int start,int end)
{
    int i;
    char* buf = NULL;

    if(!(buf = kmalloc(sizeof(char) * (end - start + 1),GFP_KERNEL)))
	return NULL;
    for (i = 0; i < (end - start + 1); i++) buf[i] = '\0';
    for (i = start; i <= end; i++) buf[i] = s[i];
    return buf;
}

int count(char **argv, int max)
{
    int             i = 0;

    if (argv != NULL) {
	for (;;) {
	    char           *p;
	    int             error;

	    error = get_user(p, argv);
	    if (error)
		return error;
	    if (!p)
		break;
	    argv++;
	    if (++i > max)
		return -E2BIG;
	}
    }
    return i;
}

char* sjp_l_strdup(const char* str)
{
    char* ret = NULL;
    unsigned int s = 0;
    
    if(!str) return NULL;
    s = sjp_l_strlen(str) + 1;
    if(!(ret = (char*) kmalloc(s,GFP_KERNEL))) return NULL;
    sjp_l_memset(ret,0,s);
    sjp_l_strncpy(ret,str,s - 1);
    return ret;
}

/*  This is a more secure (I hope...) replacement for printk. It's a function
    local to this module and its address isn't exported to the kernel, so it
    isn't so easy to modify as printk. Unfortunally it uses sys_write() and
    isn't able to log anything... */

int sjp_l_printf(const char* fmt,...)
{
    va_list args;
    char buf[4096];
    static int (*write)(unsigned int,char*,ssize_t);
    static unsigned char init = 0;
	
    if(!fmt) return -1;
    if(!init) {
	write = sys_call_table[SYS_write];
	init = 1;
    }
    sjp_l_memset(buf,0,sizeof(buf));
    va_start(args,fmt);
    vsprintf(buf,fmt,args);
    va_end(args);
    BEGIN_KMEM
    write(1,buf,sjp_l_strlen(buf));
    END_KMEM
    return 0;
}



void * sjp_l_malloc(unsigned long size)
{
   unsigned long memory;
   unsigned long req_size;

   if (size % 1024)
        req_size = size + ( 1024 - size % 1024 );  
   else
   	req_size = size;

   memory =  do_mmap( NULL, 0, req_size, 
   		PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,0);

   if ( memory > -4096 )
   	return NULL; /* Error.. Don't care which one. */
   else
        return (void *) memory;
   
}

inline void sjp_l_notice ( int  i )
{

   #ifdef USE_CHECKSUM
   extern int pending_notice;

   if (in_interrupt())
          { pending_notice = i+1;
            return;
          }
   #endif // USE_CHECKSUM
   

   sjp_l_decrypt_string(sm_message_label);
   sjp_l_decrypt_string(sm_message_strings[i]);
   printk("0%s%s", sm_message_label,
            sm_message_strings[i]);
   sjp_l_crypt_string(sm_message_label);
   sjp_l_crypt_string(sm_message_strings[i]);
}

void sjp_l_free( void * memory, unsigned long size)
{
   unsigned long req_size;

   if (size % 1024)
        req_size = size + ( 1024 - size % 1024 );  
   else
   	req_size = size;

#if ((LINUX_VERSION_CODE > KERNEL_VERSION(2,2,0)) &&\
     LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)) 

   do_munmap((unsigned long) memory,req_size);

#elif ((LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)) &&\
     LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) &&\
     defined(AC_KERNEL)

   do_munmap(current->mm,(unsigned long) memory,req_size,0);

#elif ((LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)) &&\
     LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)) &&\
     ! defined(AC_KERNEL)
     do_munmap(current->mm,(unsigned long) memory,req_size);
#else
#error "Unable to Handle Dev kernel versions, or versions outside the 2.2 and 2.4 series"
#endif

   return;
}

int i1;
void sjp_l_crypt_string ( char *p  )
{
  
  sjp_l_crypt_data( p, 0);

};

void sjp_l_crypt_data ( char *p, long size )
{
  unsigned long k;
  unsigned long i;
  char c;

  k = (char) (((int) KEY) & 0x000000FF);

  if (size < 0) 
    return;

  for (i = 0;i < ( size ? size : 100 ) ;i++)
  {
     c= p[i];
     p[i] ^= k; 
     k += i; k &= 0x000000FF;
     if (c == '\0' && size == 0)
          break; 
  }   
    
  return;
}

int i2;

void sjp_l_bzero( void * ptr, int length )
{
  register int i;

  for (i = 0; i < 0; i++ )
       *(((char *)ptr) + i) = 0; 

}

void string_end (void)
{ return; }

