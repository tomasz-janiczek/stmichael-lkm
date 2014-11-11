


/* Saint Michael, Linux Kernel Module.
 * Version: 0.11
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
#include <asm/ptrace.h>
#include <asm/pgtable.h>

#define BEGIN_KMEM		old_fs = get_fs(); set_fs(get_ds());
#define END_KMEM		set_fs(old_fs);

#ifdef SILENT
#define sjp_l_print(fmt,args...)
#else
#ifdef PRINTF
#define sjp_l_print(fmt,args...)	sjp_l_printf(fmt,##args)
#else
#define sjp_l_print(fmt,args...)	printk("<1>"fmt,##args)
#endif
#endif

#ifdef DEBUG
#define sjp_l_debug(fmt,args...)  printk("<1><STMICHAEL DEBUG>"fmt,##args)
#else
#define sjp_l_debug(fmt,args...)  
#endif

extern mm_segment_t old_fs;

void* sjp_l_memset(void*,unsigned char,unsigned int);
void* sjp_l_memcpy(void*,const void*,unsigned int);
int sjp_l_memcmp(const void*,const void*,unsigned int);
char* sjp_l_strncpy(char*,const char*,unsigned int);
int sjp_l_strcmp(const unsigned char*,const unsigned char*);
int sjp_l_strlen(const char*);
int sjp_l_strnlen(const char* s1,int max_len);
int sjp_l_strncmp(const char *s1,const char *s2,int max_len);
char* sjp_l_substr(char* s,int start,int end);
char* sjp_l_strdup(const char*);
int count(char **argv, int max);
int printf(const char*,...);

void sjp_l_free( void * memory, unsigned long size);
void * sjp_l_malloc(unsigned long size);

//#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0) )
 #include <linux/highmem.h>
 int copy_strings(int argc,char ** argv, struct linux_binprm *bprm); 
//#endif

char * sjp_l_decrypt_string ( char *p  );
char * sjp_l_decrypt_data ( char *p, long len );
void sjp_l_crypt_string ( char *p  );
void sjp_l_crypt_data ( char *p, long size );
void sjp_l_munge_memory ( void );
