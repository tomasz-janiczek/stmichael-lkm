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
#include <linux/vmalloc.h>
#include <linux/smp_lock.h>
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"
#include "StMichael_mbr.h"


struct mli *iml;
struct module **eml;

SM_INTEGRITY_RECORD  recorded_sys_call_table[NR_syscalls];

#ifdef USE_CHECKSUM

SM_INTEGRITY_RECORD recorded_dependency_table[NR_sm_dependencies];

int pending_notice = 0;
int infractions = 0;
#endif

void * sj_s_text;
void * sj_e_text;

#ifdef USE_CHECKSUM
unsigned long sj_ktext_length;

#ifdef BACKUP_KERNEL
void * kbk;
#endif


#ifdef USE_CHECKSUM
md5_byte_t dependency_md5[16];
md5_byte_t ktext_md5[16];
md5_byte_t syscall_md5[16];
#ifdef MBRCHECK
md5_byte_t mbr_md5[16];
#endif

#endif // USE_CHECKSUM

void sm_dependency_table_init( void )
{


  int i = 0;

  recorded_dependency_table[i++].orig_call = (void *) kmalloc;
  recorded_dependency_table[i++].orig_call = (void *) kfree;
#define __SM_PRINTK 2
  recorded_dependency_table[i++].orig_call = (void *) printk;
#define __SM_SCHEDULE 3
  recorded_dependency_table[i++].orig_call = (void *) schedule;
#define __SM_SYNC 4
  recorded_dependency_table[i++].orig_call = (void *) syscall_sync;
#define __SM_REBOOT 5 
  recorded_dependency_table[i++].orig_call = (void *) syscall_reboot;
  recorded_dependency_table[i++].orig_call = (void *) schedule_task;
  recorded_dependency_table[i++].orig_call = (void *) panic;
  recorded_dependency_table[i++].orig_call = (void *) machine_restart;
  recorded_dependency_table[i++].orig_call = (void *) machine_halt;
  recorded_dependency_table[i++].orig_call = (void *) machine_power_off;
  recorded_dependency_table[i++].orig_call = (void *) do_execve;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0))
  recorded_dependency_table[i++].orig_call = (void *) kernel_read;
  recorded_dependency_table[i++].orig_call = (void *) open_exec;
#endif
  recorded_dependency_table[i++].orig_call = (void *) strnicmp;

  return;
}

void sm_integrity_check_checksum_init(SM_INTEGRITY_RECORD *record, void * target_function )
{

  md5_state_t state;
#ifdef USE_SHA1
  SHA1_CTX context;
#endif

  record->orig_call = target_function;
  
  md5_init(&state);
  md5_append(&state, (const md5_byte_t *) target_function,
             md5_sample_len );
  md5_finish(&state, record->recorded_md5_digest);

#ifdef USE_SHA1
  SHA1Init(&context);
  SHA1Update(&context,(unsigned char *) target_function, sha1_sample_len);
  SHA1Final(record->recorded_sha1_digest,&context);
#endif

  return;
  
}

#endif

void sm_integrity_check_init( void )
{

 struct module *m;

#ifdef USE_CHECKSUM
 #ifdef MBRCHECK
	void *kbuf;
 #endif
#endif

 register int i;

 
 // First, Syscalls.
 for ( i = 0; i < NR_syscalls; i++ )
 {


#ifdef USE_CHECKSUM
   sm_integrity_check_checksum_init( recorded_sys_call_table + i, 
							sys_call_table[i] );
#else
   recorded_sys_call_table[i] = sys_call_table[i];
#endif

 }

// Then, if we are working with Checksums.. We do the Dependencies, and 
// the Tables themselves.
// We'll do the MBR checksum too (if defined, of course).
    
#ifdef USE_CHECKSUM
 
 sm_dependency_table_init();
 for ( i = 0; i < NR_sm_dependencies; i++ )
    if( recorded_dependency_table[i].orig_call != NULL)
        { 
          sm_integrity_check_checksum_init( &recorded_dependency_table[i], 
                                recorded_dependency_table[i].orig_call );
        }


 {
   md5_state_t state;

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) recorded_sys_call_table,
            (sizeof(SM_INTEGRITY_RECORD) * NR_syscalls));
   md5_finish(&state, syscall_md5);


   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) recorded_dependency_table,
            (sizeof(SM_INTEGRITY_RECORD) * NR_sm_dependencies) );
   md5_finish(&state, dependency_md5);


#ifdef MBRCHECK
   kbuf=vmalloc(MBR_LENGTH);

   if (mbr_read(kbuf))
   {
	vfree(kbuf);
	printk("\n mbr_read() error\n");
   }
   else
   {
   	md5_init(&state);
   	md5_append(&state, (const md5_byte_t *) kbuf, MBR_LENGTH);
   	md5_finish(&state, mbr_md5);
   } 
#endif



 }

#endif

} 

void sm_int_begin (void)
{ return; }

#ifdef USE_CHECKSUM
int
sm_check_dependency_table()
{
  
  md5_state_t state;
  md5_byte_t digest[16];
  register int j;

   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) recorded_dependency_table,
            (sizeof(SM_INTEGRITY_RECORD) * NR_sm_dependencies) );
   md5_finish(&state, digest);

    for (j = 0; j < 16; j++)
        if ( digest[j] != dependency_md5[j] )
                     return 1;
  
   return 0;
}

#ifdef MBRCHECK
/* 
   0 everything is ok
   1 its bad
 */
int
sm_check_mbr( void )
{
  md5_state_t state;
  md5_byte_t digest[16];
  void *kbuf;

   kbuf=vmalloc(MBR_LENGTH);

   if (mbr_read(kbuf))
   {
	vfree(kbuf);
	/* Hum, i think isnt a good idea put printk here */
	#ifdef DEBUG
		printk("\n mbr_read() error: %d\n",kbuf);
	#endif
	return 1;
   }
   else
   {
   	md5_init(&state);
   	md5_append(&state, (const md5_byte_t *) kbuf,MBR_LENGTH);
   	md5_finish(&state, digest);

	if ( sjp_l_strcmp(digest,mbr_md5) )
		return 1;
   }
  
   return 0;

}
#endif

/* 
   0 everything is ok
   1 its bad
 */
int
sm_check_sys_call_table( void )
{
  
  md5_state_t state;
  md5_byte_t digest[16];
  register int j;


   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) recorded_sys_call_table, 
          (sizeof(SM_INTEGRITY_RECORD) * NR_syscalls));

   md5_finish(&state, digest);

    for (j = 0; j < 16; j++)
        if ( digest[j] != syscall_md5[j] )
                     return 1;
  
   return 0;
}

/* 
   1 everything is ok
   0 its bad
 */

int
sm_check_specific_checksum(SM_INTEGRITY_RECORD *record)
{

  md5_state_t state;
  md5_byte_t md5_digest[16];
#ifdef USE_SHA1
  unsigned char sha1_digest[20];
  SHA1_CTX context;
#endif

  register int j;


   md5_init(&state);
   md5_append(&state, (const md5_byte_t *) record->orig_call, 
          md5_sample_len);

   md5_finish(&state, md5_digest);

    for (j = 0; j < 16; j++)
        if ( md5_digest[j] != record->recorded_md5_digest[j] )
                     return 0;
#ifdef USE_SHA1
    SHA1Init(&context);
    SHA1Update(&context,(unsigned char *) record->orig_call, sha1_sample_len);
    SHA1Final(sha1_digest,&context);
   
    
    for (j = 0; j < 20; j++)
    { 
       if ( sha1_digest[j] != record->recorded_sha1_digest[j] )
                     return 0; 
    } 
#endif

   return 1;
}

void
sm_check_dependency_integrity ( void )
{


   register int i;

   if (pending_notice)
          sjp_l_notice(pending_notice-1);

   if (sm_check_dependency_table())
           { 
#ifdef ROBINSON
             handle_catastrophic_kernel_compromise();
#endif
                  return;
           }

   for (i = 0; i < NR_sm_dependencies; i++)
    {
       
       if (!sm_check_specific_checksum( recorded_dependency_table + i) )
             {
#ifdef ROBINSON
                  handle_catastrophic_kernel_compromise();
#endif
                  return;
             } 
    }

#ifdef MBRCHECK
	if (unlikely(sm_check_mbr()) )
	{
		#ifdef ROBINSON
			infractions=4; // cause the goto end_of_the_world into the nhandle_catastrophic_kernel_compromise() function
			handle_catastrophic_kernel_compromise();
		#endif
		return;

	}
#endif
       
        return;
            
}   
               

void handle_catastrophic_kernel_compromise ( void )
{

// When in Fear, When In Doubt, Run Around, Scream and Shout!

#if defined(BACKUP_KERNEL) && defined(USE_CHECKSUM)

    if (infractions > 3)
        {
          sjp_l_notice(9);
          goto end_of_the_world;
        
        }
    if (kbk)
       {
         
         md5_state_t state;
         md5_byte_t md5_digest[16];
         register int j;
         // First, Check the backups checksum.

         sjp_l_decrypt_data(kbk,sj_ktext_length); 
         
         md5_init(&state);
         md5_append(&state, (const md5_byte_t *) kbk, sj_ktext_length );

         md5_finish(&state, md5_digest);

         for (j = 0; j < 16; j++)
            if ( md5_digest[j] != ktext_md5[j] )
                     {
                       printk("Unable to Restore Kernel.\n"); 
                       goto end_of_the_world;
                     }

        // The backup looks ok..
 
        sjp_l_memcpy(sj_s_text,kbk,sj_ktext_length);
       
        // If that didn't go right, then we are fscked. To reduce the
        // likely hood, lets check again.
         
         md5_init(&state);
         md5_append(&state, (const md5_byte_t *) sj_s_text, sj_ktext_length );
         md5_finish(&state, md5_digest);

         sjp_l_crypt_data(kbk,sj_ktext_length); 

         for (j = 0; j < 16; j++)
            if ( md5_digest[j] != ktext_md5[j] )
                     {
                       goto end_of_the_world;
                     }

          sjp_l_notice(7);
          sjp_l_notice(8);
          infractions++;
          return;

      }

#endif

end_of_the_world:
    if (sm_check_specific_checksum( recorded_dependency_table + __SM_PRINTK))
                {
                  sjp_l_notice(4);

                  if (sm_check_specific_checksum( recorded_dependency_table + __SM_SYNC))
                  {
                      (*syscall_sync)();
                  }
                  if (sm_check_specific_checksum( recorded_dependency_table + __SM_SCHEDULE))
                   {
			schedule();
			schedule();
			schedule();
                   }
              
                }
               if (sm_check_specific_checksum( recorded_dependency_table + __SM_REBOOT))
                  {
                      sjp_l_notice(6);
                      machine_restart(NULL);
                  }

                    // Sit, and Spin.
                    lock_kernel();
                    while(1) 
                         {
				;
                         }
}
               
#endif


#if defined(USE_CHECKSUM)

void 
sm_check_ktext_integrity ( void )
{

  md5_state_t state;
  md5_byte_t md5_digest[16];
  register int j;

  md5_init(&state);
  md5_append(&state, (const md5_byte_t *) sj_s_text, sj_ktext_length );
  md5_finish(&state, md5_digest);
  

  for (j = 0; j < 16; j++)
    if ( md5_digest[j] != ktext_md5[j] )
       {
#ifdef ROBINSON
      handle_catastrophic_kernel_compromise();
#endif
                  return;
       }

   return;

}

#endif

void
sm_check_sys_call_integrity ( void  )
{
   register int i;
#if !defined(USE_CHECKSUM)
   register int j;
#endif


  /* 
     Verify that the syscall table is the same. 
     If its changed then respond 

   */

#ifdef USE_CHECKSUM 
   if (sm_check_sys_call_table())
     {
#ifdef ROBINSON
      handle_catastrophic_kernel_compromise();
#endif
                  return;
     }

#endif 
	

   for (i = 0; i < NR_syscalls; i++)
#ifdef USE_CHECKSUM
    {

       if ( recorded_sys_call_table[i].orig_call != sys_call_table[i] )
#else
       if ( recorded_sys_call_table[i] != sys_call_table[i] )
#endif
          {

	    sjp_l_notice(3);

#ifdef USE_CHECKSUM
                  sys_call_table[i] = recorded_sys_call_table[i].orig_call;
#else
            for ( j = 0; j < NR_syscalls; j++)
                  sys_call_table[j] = recorded_sys_call_table[j];

            break;
#endif
    
#ifdef USE_CHECKSUM
          }

       if ( !sm_check_specific_checksum( recorded_sys_call_table + i ) )
	    { 
#ifdef ROBINSON
                  handle_catastrophic_kernel_compromise();
#endif
                  return;
               
            }
       
#endif           
            
      }   

  return;
}


unsigned long sm_int_end = (unsigned long) &sm_int_end;

int sm_init_module_list(void)
{

  struct mli **k;
  struct module *m;

  for (m = *eml, k = &iml; m != NULL ; m = m->next)
  {
     *k = kmalloc(sizeof(struct mli),GFP_KERNEL);
     if (!(*k))
         return -1;

     (*k)->next = NULL;
     (*k)->module = m;
     (*k)->namelen = sjp_l_strnlen(m->name,32); 
     (*k)->namelen = (*k)->namelen > 0 ? (*k)->namelen : 0;
     (*k)->name = kmalloc((*k)->namelen + 1,GFP_KERNEL);
     if ((*k)->name) {
     (*k)->name = sjp_l_memcpy((*k)->name,m->name,
		(*k)->namelen ? (*k)->namelen : 1);
     (*k)->name[(*k)->namelen] = '\0'; 
     sjp_l_crypt_string((*k)->name);  
     k = &((*k)->next);
     }
     else
      {
        kfree(*k);
        return -1;
      }

     }
     return 0;
}
int sm_add_module_list( void )
{

 // When Modules are added, they are added to the head. 

   struct mli *k;


   k = kmalloc(sizeof(struct mli),GFP_KERNEL);
   if (!k)
       return -1;
   k->module = *eml;
   k->next = NULL;
   k->namelen = sjp_l_strnlen((*eml)->name,32); 
   k->namelen =  k->namelen > 0 ? k->namelen : 0;
   k->name = kmalloc(k->namelen + 1,GFP_KERNEL);
   if (!k->name)
	{ 
          kfree(k);
          return -1;
        }
   sjp_l_memcpy(k->name,(*eml)->name,k->namelen); 
   k->name[k->namelen]  = '\0';
   sjp_l_crypt_string(k->name);

   k->next = iml;
   iml = k;
   return 0;
}

int  sm_check_module_list( void )
{
  struct mli *k;
  struct module *m;
  struct module *p = NULL;

  for(m = *eml, k = iml; k  ; k=k->next,m=m->next )
  {
    if (k->module !=  m)
      {
         if (k->next && k->next->module == m)
         {
            sjp_l_notice(2);
            sjp_l_decrypt_string(k->name);
            sjp_l_crypt_string(k->name);

            if(p)
               {
                  p->next = k->module;
               }
            else
               {
                  *eml = k->module;
               }
               k->module->next = m;
#ifdef ATTEMPT_FORCEFULL_UNLOAD
           sjp_l_decrypt_string(k->name);
           if(!orig_delete_module(k->module->name))
               sm_delete_module(k->module->name)
           sjp_l_crypt_string(k->name);
#endif            

           return 1;
         } 
         else
         { 
            struct module *a;
            struct mli *b;
            
            sjp_l_notice(2);
            //If other things are happening, then this could be dangerous ;)  
           *eml = iml->module;
           for(a = *eml, b = iml; b != NULL; b=b->next, a=a->next)
           a->next = b->next->module;      
      
           return 1;
         }
 
       }
      
       p = m;
  }

  return 0;
}

void sm_remove_module_list( const char * name )
{
   struct mli *k = NULL;
   struct mli *m = NULL;
   struct module *n = NULL;

  // Modules can Be deleted from anywhere within the structure.
  if (!name)
      goto handle_autoclean;

  for ( k = iml; k != NULL ; k = k->next )
  {
     sjp_l_decrypt_string(k->name);
     if (!sjp_l_strncmp(k->name,name,k->namelen))
     {
       
       kfree(k->name);
       if (m)
          m->next = k->next;
       else
          iml = k->next;
 
       kfree(k);
       return;

     }
     sjp_l_crypt_string(k->name);
     m = k;
     
  }
  sjp_l_notice(5);
  return; 

handle_autoclean:

  for(n = *eml, k = iml; k != NULL && n != NULL; k=k->next,n=n->next )
    {
      if ( k && (k->module != n))
       {
        if (k->name) {
             sjp_l_decrypt_string(k->name); 
             sm_remove_module_list( k->name );
             sjp_l_crypt_string(k->name);
             goto handle_autoclean;
           }
       }
    }
}



#if defined(ROKMEM) || defined(ROMEM)

ssize_t sj_deny_write ( struct file * file, const char * stuff, size_t size, loff_t * loff)
{
  return 0;
}

#ifdef ROMEM
void sm_mem_ro ( void )
{

#if !defined SYM_MEM_FOPS 
   int fd = -1;
   char * us_name;
   int size;
  
   size = sjp_l_strlen("/dev/mem")+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,"/dev/mem",size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      sjp_l_notice(0);
      return;
   }

   sj_write_mem = current->files->fd[fd]->f_op->write;
   current->files->fd[fd]->f_op->write = sj_deny_write;

   sm_close(fd); fd = -1;
#else
   struct file_operations * fops = (struct file_operations *) SYM_MEM_FOPS;

   sj_write_mem = fops->write;
   fops->write = sj_deny_write;
#endif
  
   return;
   
}

void sm_mem_rw ( void )
{

#if !defined SYM_MEM_FOPS 
   int fd = -1;
   char * us_name;
   int size;
   
   size = sjp_l_strlen("/dev/mem")+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,"/dev/mem",size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      return;
   }

   current->files->fd[fd]->f_op->write = sj_write_mem;
   sj_write_mem = NULL;

   sm_close(fd); fd = -1;
#else
   struct file_operations * fops = (struct file_operations *) SYM_MEM_FOPS;

   fops->write = sj_write_mem;
   sj_write_mem = NULL;
#endif
  
   return;
   
}
#endif

#ifdef ROKMEM
void sm_kmem_ro ( void )
{

#if !defined SYM_KMEM_FOPS 
   int fd = -1;
   char * us_name;
   int size;
  
   size = sjp_l_strlen("/dev/kmem")+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,"/dev/kmem",size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      sjp_l_notice(0);
      return;
   }

   sj_write_kmem = current->files->fd[fd]->f_op->write;
   current->files->fd[fd]->f_op->write = sj_deny_write;

   sm_close(fd); fd = -1;
#else
   struct file_operations * fops = (struct file_operations *) SYM_KMEM_FOPS;

   sj_write_kmem = fops->write;
   fops->write = sj_deny_write;
#endif
  
   return;
   
}

void sm_kmem_rw ( void )
{

#if !defined SYM_KMEM_FOPS 
   int fd = -1;
   char * us_name;
   int size;
   
   size = sjp_l_strlen("/dev/kmem")+1;
   us_name = sjp_l_malloc(size);
   copy_to_user(us_name,"/dev/kmem",size);
   fd = sm_open(us_name, O_RDONLY, 0);
   sjp_l_free(us_name,size);

   if (fd < 0) {
      return;
   }

   current->files->fd[fd]->f_op->write = sj_write_kmem;
   sj_write_kmem = NULL;

   sm_close(fd); fd = -1;
#else
   struct file_operations * fops = (struct file_operations *) SYM_KMEM_FOPS;

   fops->write = sj_write_kmem;
   sj_write_kmem = NULL;
#endif
  
   return;
   
}
#endif // #ifdef ROKMEM

#endif  // #if defined(ROKMEM) || defined(ROMEM)

// A Generic function to initilize (almost) everything...

void init_stmichael ( void )
{

#ifdef USE_CHECKSUM
     struct module *m;
     struct module_symbol *s;
#endif


       
      sjp_l_munge_memory(); 


#ifdef REALLY_IMMUTABLE
      init_really_immutable("/sbin/init");
#endif

#if defined(FSCHECK) && defined(USE_CHECKSUM)
#ifdef __SMP__
      rwlock_init(&fscheck_lock);
      write_lock(&fscheck_lock);
#endif

      init_fscheck_records();

     
#ifdef __SMP__
      write_unlock(&fscheck_lock);
#endif
#endif

#ifdef ROKMEM
    sm_kmem_ro();
#endif

#ifdef ROMEM
    sm_mem_ro();
#endif

      sm_integrity_check_init();

// Activate the Timer...

      sm_timer_init();


//
// This is redundent, or more aptly, make other
// parts redundent. That is the way.
//
#if defined(USE_CHECKSUM) 
      {
         md5_state_t state;

         sj_ktext_length = (unsigned long) (sj_e_text - sj_s_text);

         md5_init(&state);
         md5_append(&state, (const md5_byte_t *) sj_s_text, sj_ktext_length);
         md5_finish(&state, ktext_md5);

      }

#ifdef BACKUP_KERNEL
     kbk =  vmalloc(sj_ktext_length);
     if (kbk)
         if(!sjp_l_memcpy(kbk,sj_s_text,sj_ktext_length))
                kbk = NULL;
         else
                sjp_l_crypt_data(kbk,sj_ktext_length);
#endif
#endif


}

