/* Saint Michael, Linux Kernel Module.
 * Verions: 0.10
 *
 * March 25, 2002
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


#ifdef __SMP__
 #include <asm/spinlock.h>
#endif

#include <linux/version.h>

#define VERSION "StMichael 0.12"
#define BUFFSIZE 256

//
// Primary init function for our data structures.
//
 void init_stmichael( void );

#ifdef USE_CHECKSUM

 #include "md5.h"
 #include "sha1.h"
 #include "StMichael_Ref.h"

 #define md5_sample_len 31
 #define sha1_sample_len 31

 #ifdef FSCHECK

  struct fscheck_record {
   md5_byte_t file_operations_digest[16];
   md5_byte_t directory_operations_digest[16];
   md5_byte_t dentry_operations_digest[16];
   md5_byte_t super_operations_digest[16]; 
   struct file_operations * dir_operations;
   struct file_operations * file_operations;
   struct super_operations * super_operations;
   struct dentry_operations * dentry_operations;
  }; 

  #endif

// 
// Subbordinate setup functions to init_stmichael
//
 #if defined(FSCHECK)
  int init_fscheck_record( struct fscheck_record * rec, char * filename , char * dirname);
  void check_fscheck_record( struct fscheck_record * rec, char * filename, char * dirname );
  int init_fscheck_records( void );
  void check_fscheck_records( void );
 #endif
 
 
 typedef struct sm_syscall_record
 {
   void *orig_call;
   md5_byte_t recorded_md5_digest[16];
   unsigned char recorded_sha1_digest[20];
 }
 SM_INTEGRITY_RECORD;

#else
 typedef void *SM_INTEGRITY_RECORD;
#endif

#ifdef __SMP__
 rwlock_t sm_running;
 #ifdef FSCHECK
  rwlock_t fscheck_lock;
 #endif
#endif

extern void *sys_call_table[];


asmlinkage long (*orig_init_module) (const char *name,
				     struct module * mod_user);
int (*orig_delete_module) (const char *name);
int (*orig_exit) (const int error);

//
// Some stuff we will need if we have to reboot the box.
//
long (*syscall_reboot) (int magic1, int magic2, unsigned int cmd, void * arg);
void (*syscall_sync) (void);

//
// The original exit system call for replacement.
//
int (*syscall_exit) (const int error);

//
// If we intend to make kmem read only, we need these.
//
#ifdef ROKMEM
 ssize_t (*sj_write_kmem)(struct file * file, const char * buf, 
		  size_t count, loff_t *ppos);
#endif

#ifdef ROMEM
 ssize_t (*sj_write_mem)(struct file * file, const char * buf, 
		  size_t count, loff_t *ppos);
#endif


//
// If we touch the filesystem, we will need to know these.
//
#if defined(FSCHECK) || defined(ROKMEM) || defined(REALLY_IMMUTABLE) || defined(ROMEM)
 asmlinkage long (*sm_open)( const char * filename, int flags, int mode );
 asmlinkage long (*sm_close)( int fd );
#endif

//
// Systemcall replacements for init_module, delete_module, and exit()
//
asmlinkage long sm_init_module (const char *name, struct module *mod_user);
int sm_delete_module (const char *name);
int sm_exit (const int error);

//
// Stuff for the non-removable immutable flag code.
//
#ifdef REALLY_IMMUTABLE
 int init_really_immutable ( char * filename);

 int sm_ext2_ioctl (struct inode * inode, struct file * filp, unsigned int cmd,
			unsigned long arg );
 int (*orig_ext2_ioctl) ( struct inode * inode, struct file * filp,
			unsigned int cmd, unsigned long arg );
#endif

//
// Checksum specific functions.
//
#ifdef USE_CHECKSUM
void sm_integrity_check_checksum_init(SM_INTEGRITY_RECORD *record, void * target_function );
int sm_check_dependency_table( void );
int sm_check_sys_call_table( void );
int sm_check_specific_checksum(SM_INTEGRITY_RECORD *record);
void sm_check_dependency_integrity ( void );
void handle_catastrophic_kernel_compromise ( void );
#endif

void sm_integrity_check_init( void );
void sm_check_sys_call_integrity ( void  );
void sm_check_ktext_integrity ( void );

//
// How many dependencies do we have?
//
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,3,99))
#define NR_sm_dependencies 15
#else
#define NR_sm_dependencies 13
#endif


//
// Sets up the module list stuff.
//
int sm_init_module_list(void);


//
// Module list datastructure.
//
struct mli {
    struct module * module;
    char * name;
    int namelen;
    struct mli *next;
};

//
// Subordinate functions to the module initlization function.
//
int sm_add_module_list( void );
int  sm_check_module_list( void );
void sm_remove_module_list( const char * name );

asmlinkage unsigned long sm_create_module (const char *name, size_t size);
asmlinkage unsigned long (*orig_create_module) (const char *name, size_t size);


