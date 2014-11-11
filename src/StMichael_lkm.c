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
#include <linux/smp_lock.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <sys/syscall.h>
#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <linux/smp_lock.h>
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"
#include "StMichael_timer.h"

extern void *sj_s_text;
extern void *sj_e_text;

#define IS_IN_KERNEL_TEXT(addr)\
        (addr > (long)sj_s_text && addr < (long)sj_e_text) ? (1) : (0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,9)
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
#endif

int
init_module(void)
{
    extern struct module **eml;
    extern struct module *iml;
    struct module *m, **v;
    struct module_symbol *s;
    int i;
    extern void * sm_start;
    extern void * sm_end;
 
    lock_kernel();
#ifdef __SMP__
    rwlock_init(&sm_running);
#endif

    sjp_l_print("--=={Loading %s \n", VERSION);

       // Now ya see me
       for ( m = THIS_MODULE; m->next != NULL; m = m->next );

       v = (struct module **) (++m);
#ifdef CLOAK
       *v = (THIS_MODULE)->next;
       // Now ya don't.
#endif
       eml = v;
       iml = NULL;

      sj_s_text = (void *) (PAGE_OFFSET|0x00100000);
      for ( m = *eml; m->next; m = m->next );
      for ( s = m->syms; s->name; s++ );
      sj_e_text = (void *) s;

      // Although we should be the first to load, sometimes it
      // may be usefull to use us to look for unsophistocated 
      // LKM-RK's. This is an unexpensive test that uses what we 
      // allready have, so why not?
      //

      for ( i = 0; i < NR_syscalls; i++ )
           if (!IS_IN_KERNEL_TEXT((long)sys_call_table[i]))
             {   
                 printk("(STMICHAEL) Possible LKM Rootkit Detected during Load.\n");
                 printk("(STMICHAEL) Unable to Perform Recovery. Load of StMichael Aborted.\n");
                 printk("(STMICHAEL) If this message is being erronously generated, Read the NOTE in StMichael_lkm.c\n");
              

// NOTE NOTE NOTE NOTE NOTE NOTE NOTE
// If you are recieving a notice that the kenrel is comprimised on
// Load AND you have validated that there is no Rootkid present, but
// that the cause of the error message is caused by a legitimate module.
// Then uncomment the following line:
//         if(0)

                 return -1;

// Also, contact me (lawless@wwjh.net) with specifics on your configuration
// So that I may account for it, and test it in simulation.
// Thanks.

             }

    orig_init_module = sys_call_table[__NR_init_module]; 
    orig_delete_module = sys_call_table[__NR_delete_module];
    orig_exit = sys_call_table[__NR_exit];
    orig_create_module = sys_call_table[__NR_create_module];

#if defined(FSCHECK) || defined(ROKMEM) || defined(REALLY_IMMUTABLE)
    sm_open = sys_call_table[__NR_open]; 
    sm_close = sys_call_table[__NR_close]; 
#endif

    syscall_reboot = sys_call_table[__NR_reboot];
    syscall_sync = sys_call_table[__NR_sync];

    sys_call_table[__NR_init_module] = sm_init_module;
    sys_call_table[__NR_delete_module] = sm_delete_module; 
    sys_call_table[__NR_create_module] = sm_create_module; 
    //sys_call_table[__NR_exit] = sm_exit; 



    if (sm_init_module_list())
         return -1;

    init_stmichael();

    sjp_l_print("--=={%s Successfully Loaded\n", VERSION);

    {

      // This function will self destruct in 5 miliseconds...

      unsigned long filler = 0x00000000;
      unsigned long *p;

      for ( p = (unsigned long *) &m;
            p < (unsigned long *) &filler;
            p++)
		*p = filler;
 

    }

    sjp_l_bzero((void *) (THIS_MODULE), sizeof(struct module));

    unlock_kernel();
    return 0;
}

void
cleanup_module(void)
{
  // We can't unload, not now. not no more.
  return;

}

