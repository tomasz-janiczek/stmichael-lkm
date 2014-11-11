#define MODULE
#define __KERNEL__

/* Saint Michael, Linux Kernel Module.
 * Demo LKM
 *
 * June 15, 2001
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

int (*orig_void_module) (int i);

extern void *sys_call_table[];

int new_void_module ( int i )
{

 printk("Void Module");
 return 0;

}

int
init_module(void)
{
#ifdef TEST_FOUR
    int i;
    char *filename = "/usr/bin/uptime";
    char *argv[] = { "/usr/bin/uptime", NULL };
    struct pt_regs regs;
#endif 

#ifdef TEST_TWO
    char * c;
    printk("About to Trash the Kernel's Delete Module..\n ");
    printk("If StMichael isn't in here, prepare for a panic.\n");
#endif

#ifdef TEST_ONE
    printk("About to try replacing a systemcall... \n");
#endif

#ifdef TEST_FIVE
    char * c;
    printk("About to attack StMichael itself....\n");
    printk("StMichael May Halt the System or Do other Nasty Stuff...\n");
#endif

#ifdef TEST_THREE
   struct module *m, **v;

   printk("This checks the Anti-LKM Concealment\n");
#endif


#ifndef TEST_FIVE    
    orig_void_module = sys_call_table[SYS_swapoff]; 
#else
    orig_void_module = sys_call_table[SYS_delete_module];
#endif


#ifdef TEST_ONE
    sys_call_table[SYS_swapoff] = new_void_module;
#endif

#ifdef TEST_TWO
    c = (char *) orig_void_module;
    printk("Replacing Code at %x.\n", orig_void_module);
    c[1] = 'D';
    c[2] = 'E';
    c[3] = 'A';
    c[4] = 'D';
    c[5] = 'B';
    c[6] = 'E';
    c[7] = 'E';
    c[8] = 'F';
#endif

#ifdef TEST_THREE
    for ( m = THIS_MODULE; m->next != NULL; m = m->next );
    v = (struct module **) (++m);
    *v = (THIS_MODULE)->next;
#endif

#ifdef TEST_FOUR
    // somethin better be loaded ;)
    i = do_execve(filename,argv, NULL, &regs);
    printk("Returned: %d\n",i);
#endif 

#ifdef TEST_FIVE
    c = (char *) orig_void_module;
    printk("Replacing Code at %x.\n", orig_void_module);
    c[1] = 'D';
    c[2] = 'E';
    c[3] = 'A';
    c[4] = 'D';
    c[5] = 'B';
    c[6] = 'E';
    c[7] = 'E';
    c[8] = 'F';
#endif
    

    return 0;

}

void
cleanup_module(void)
{
  printk("Removing Test Module.\n");
  return;

}


