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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <sys/syscall.h>
#include <asm/errno.h>
#include <linux/reboot.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"
#include "StMichael_Ref.h"
#include "md5.h"



#if defined(FSCHECK) && defined(USE_CHECKSUM)
 struct fscheck_record ext2_fscheck_record;
 struct fscheck_record proc_fscheck_record;
 md5_byte_t ext2_fscheck_digest[16];
 md5_byte_t proc_fscheck_digest[16];
#endif

#ifdef REALLY_IMMUTABLE

int init_really_immutable ( char * filename )
{

   #if defined(EXT_FILE_OPS)
   	struct file_operations * fops = (struct file_operations *) EXT_FILE_OPS;
   #endif


#if ! defined(EXT_FILE_OPS) 
   char * us_name;
   int fd = -1;
   int size;
   size = sjp_l_strlen(filename)+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,filename,size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      sjp_l_notice(0);
      return -1;
   }

   if ((!sjp_l_strncmp("ext2",
         current->files->fd[fd]->f_dentry->d_sb->s_type->name,5)
          || !sjp_l_strncmp("ext3", 
              current->files->fd[fd]->f_dentry->d_sb->s_type->name,5))
          && orig_ext2_ioctl == NULL)
      {
      
        orig_ext2_ioctl = current->files->fd[fd]->f_op->ioctl; 
        current->files->fd[fd]->f_op->ioctl = (void *) sm_ext2_ioctl;

      }
   sm_close(fd);
#else
   orig_ext2_ioctl = fops->ioctl;
   fops->ioctl = (void *) sm_ext2_ioctl;
#endif

   return 0;
}

int sm_ext2_ioctl ( struct inode * inode, struct file * filp,
		unsigned int cmd, unsigned long arg )
{
     unsigned int flags;

        if ( inode->u.ext2_i.i_flags & S_IMMUTABLE )
        { 
          if ( get_user(flags, (int *) arg ))
                   return -EFAULT;

           // Lets keep it that way..  
           flags |= S_IMMUTABLE ;

           if ( put_user(flags, (int *) arg ))
                   return -EFAULT;

          }

        return orig_ext2_ioctl( inode, filp, cmd, arg ) ;
}

#endif

#if defined(FSCHECK) && defined(USE_CHECKSUM)
int init_fscheck_record( struct fscheck_record * rec, char * filename, char * dirname )
{

   int fd = -1;
   char * us_name;
   int size;
   md5_state_t state;
   struct file_operations *fops;
   struct super_operations *sops;
   struct dentry_operations *dops;

   rec->dir_operations = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
   rec->file_operations = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
   rec->super_operations = kmalloc(sizeof(struct super_operations), GFP_KERNEL);
   rec->dentry_operations = kmalloc(sizeof(struct dentry_operations), GFP_KERNEL);

   if ( ! (rec->dir_operations && rec->file_operations && rec->super_operations && rec->dentry_operations ) )
      {
file_init_failure:
          if (rec->dir_operations) kfree(rec->dir_operations);
          if (rec->file_operations) kfree(rec->file_operations);
          if (rec->super_operations) kfree(rec->super_operations);
          if (rec->dentry_operations) kfree(rec->dentry_operations);
          sjp_l_notice(0);
          return -1;
      }
#if !defined(EXT_FILE_OPS) || !defined(EXT_SUPER_OPS) || !defined(PROC_FILE_OPS) || !defined (PROC_DENT_OPS) || !defined(PROC_SUPER_OPS) 

   size = sjp_l_strlen(filename)+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,filename,size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      sjp_l_notice(0);
      goto file_init_failure; 
   }

   fops = current->files->fd[fd]->f_op;

   if (!sjp_l_strncmp("/proc",filename,5))
	   dops = current->files->fd[fd]->f_dentry->d_op;
   else
	   dops = NULL;

   sops = current->files->fd[fd]->f_dentry->d_sb->s_op;
 
#else

   if (sjp_l_strncmp("/proc",filename,5))
   {
	   fops = (struct file_operations *) (EXT_FILE_OPS);
	   dops = NULL;
	   sops = (struct super_operations *) (EXT_SUPER_OPS);
   }
   else
   {	   
	   fops = (struct  file_operations *) (PROC_FILE_OPS);
	   dops = (struct  dentry_operations *) (PROC_DENT_OPS);
	   sops = (struct  super_operations *) (PROC_SUPER_OPS);
   }

#endif

   sjp_l_memcpy(rec->file_operations, fops,
              sizeof(struct file_operations));

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) fops, 
             sizeof(struct file_operations));
   md5_finish(&state, rec->file_operations_digest);

   if (dops) {
 
   	sjp_l_memcpy(rec->dentry_operations, 
			dops, 
			sizeof(struct dentry_operations));

   	md5_init(&state);
   	md5_append(&state, (const md5_byte_t *) dops, 
              		sizeof(struct dentry_operations));
   	md5_finish(&state, rec->dentry_operations_digest);
   }
   else 
	   rec->dentry_operations = NULL;


   sjp_l_memcpy(rec->super_operations, sops, sizeof(struct super_operations));

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) sops, 
        sizeof(struct super_operations));

   md5_finish(&state, rec->super_operations_digest);


#if !defined(EXT_FILE_OPS) || !defined(EXT_SUPER_OPS) || !defined(PROC_FILE_OPS) || !defined (PROC_DENT_OPS) || !defined(PROC_SUPER_OPS)
   sm_close(fd); 
   fd = -1;
#endif
  
#if !defined(EXT_DIR_OPS) || !defined(PROC_DIR_OPS)
   size = sjp_l_strlen(dirname)+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,dirname, size);
   fd = sm_open(us_name, O_RDONLY | O_DIRECTORY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      sjp_l_notice(0);
      goto file_init_failure; 
   }
   
   fops = current->files->fd[fd]->f_op;
#else
   if (sjp_l_strncmp("/proc",filename,5))
	   fops = (struct file_operations *) EXT_DIR_OPS;
   else
	   fops = (struct file_operations *) PROC_DIR_OPS;
   
#endif

   sjp_l_memcpy(rec->dir_operations, fops,
             sizeof(struct file_operations));
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) fops, 
		sizeof(struct file_operations));
   md5_finish(&state, rec->directory_operations_digest);

#if !defined(EXT_DIR_OPS) || !defined(PROC_DIR_OPS) 
   sm_close(fd); fd = -1;
#endif

   return 0;
   
}


void check_fscheck_record( struct fscheck_record * rec, char * filename, char * dirname )
{
   md5_state_t state;
   md5_byte_t digest[16];
   int i;
   int fd = -1;
   int size;
   char * us_name;

   // First, Dir options.
   size = sjp_l_strlen(filename)+1;
   us_name = sjp_l_malloc(size);
   if (!us_name)
      { 
       return;
      }
   copy_to_user(us_name,filename,size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0)
      {   
#if defined(EXT_FILE_OPS) && defined(PROC_FILE_OPS) 
	      goto check_file_not_available;
#else
          sjp_l_notice(1);
          return;
#endif
      }
  
   // File Opperations Check. 
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) current->files->fd[fd]->f_op, 
                      sizeof(struct file_operations));
   md5_finish(&state, digest);
   
   for (i = 0; i < 16; i++)
      if (digest[i] != rec->file_operations_digest[i])
         {

           sjp_l_notice(10);
           sjp_l_memcpy( current->files->fd[fd]->f_op,
                     rec->file_operations,
                     sizeof(struct file_operations));
	   break;
         }
   
   sm_close(fd); 
#if defined(EXT_FILE_OPS) && defined(PROC_FILE_OPS) 
check_file_not_available:
#endif

   fd = -1;

   size = sjp_l_strlen(dirname)+1;
   us_name = sjp_l_malloc(size);
   if (!us_name)
      { 
       sjp_l_notice(1);
       return;
      }
   copy_to_user(us_name,dirname,size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0)
      {     
#if defined(EXT_FILE_OPS) && defined(PROC_FILE_OPS) 
	      goto check_dir_not_available;
#else
          sjp_l_notice(1);
          return;
#endif
      }

   // Directory Opperations Check
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) current->files->fd[fd]->f_op, 
              sizeof(struct file_operations));
   md5_finish(&state, digest);

#ifdef DEBUG
   { int i; printk("Digest: "); for (i = 0; i < 16; i++) printk("%X", rec->directory_operations_digest[i]); printk("\n"); }
   { int i; printk("Digest: "); for (i = 0; i < 16; i++) printk("%X", digest[i]); printk("\n"); }
#endif

   for (i = 0; i < 16; i++)
      if (digest[i] != rec->directory_operations_digest[i])
         {
           sjp_l_notice(1);
           sjp_l_memcpy( current->files->fd[fd]->f_op,
                      rec->dir_operations,
                     sizeof(struct file_operations));
	   break;
         }

   // Dentry Opperations Check
   //
   if (current->files->fd[fd]->f_dentry->d_op)
   { 
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) current->files->fd[fd]->f_dentry->d_op, 
              sizeof(struct dentry_operations));
   md5_finish(&state, digest);

   for (i = 0; i < 16; i++)
      if (digest[i] != rec->dentry_operations_digest[i])
         {
           sjp_l_notice(10);
           sjp_l_memcpy( current->files->fd[fd]->f_dentry->d_op,
                      rec->dentry_operations,
                     sizeof(struct dentry_operations));
	   break;
         }
   }
   // Super Opperations Check   
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) current->files->fd[fd]->f_dentry->d_sb->s_op, 
                     sizeof(struct super_operations));
   md5_finish(&state, digest);
   
   for (i = 0; i < 16; i++)
      if (digest[i] != rec->super_operations_digest[i])
         {
           sjp_l_notice(3);
           sjp_l_memcpy( current->files->fd[fd]->f_dentry->d_sb->s_op,
                     rec->super_operations,
                     sizeof(struct super_operations));
	   break;
         }
   

   sm_close(fd); fd = -1;
check_dir_not_available:
   
   return; 
}



int init_fscheck_records( void )
{
   md5_state_t state;
    

   if (init_fscheck_record( &ext2_fscheck_record, "/sbin/init" , "/"))
            return -1;

   if (init_fscheck_record( &proc_fscheck_record, "/proc/ksyms", "/proc" ))
           return -1;
    
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) &ext2_fscheck_record, sizeof(struct fscheck_record));
   md5_finish(&state, ext2_fscheck_digest);
    
   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) &proc_fscheck_record, sizeof(struct fscheck_record));
   md5_finish(&state, proc_fscheck_digest);

   return 0;

}


void check_fscheck_records( void )
{
   md5_state_t state;
   md5_byte_t digest[16];
   int i;

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) &ext2_fscheck_record, sizeof(struct fscheck_record));
   md5_finish(&state, digest);

   for (i = 0; i < 16; i++)
      if (digest[i] != ext2_fscheck_digest[i])
         {
           sjp_l_notice(4);
           handle_catastrophic_kernel_compromise();
           return;
         }

   check_fscheck_record( &ext2_fscheck_record, "/sbin/init" , "/");
   

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) &proc_fscheck_record, sizeof(struct fscheck_record));
   md5_finish(&state, digest);
   
    for (i = 0; i < 16; i++)
       if (digest[i] != proc_fscheck_digest[i])
         {
           sjp_l_notice(4);
           handle_catastrophic_kernel_compromise();
           return;
         }
   
    check_fscheck_record( &proc_fscheck_record, "/proc/ksyms", "/proc" );

    return;
}

#endif

void sm_fs_end ( void )
{
	return;
}



