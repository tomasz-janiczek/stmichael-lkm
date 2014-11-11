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
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"



void setup_dependency_table( void );

asmlinkage long
sm_init_module (const char *name, struct module * mod_user)
{
   int init_module_return;

   init_module_return = (*orig_init_module)(name,mod_user);
   
  /* 
     Verify that the syscall table is the same. 
     If its changed then respond 

     We could probably make this a function in itself, but
     why spend the extra time making a call?

   */

   
#ifdef USE_CHECKSUM
   sm_check_dependency_integrity();
#endif

   sm_check_sys_call_integrity();

   sm_check_module_list();

#if defined(FSCHECK) && defined(USE_CHECKSUM)
#ifdef __SMP__
 write_lock(&fscheck_lock);
#endif
 check_fscheck_records();
#ifdef __SMP__
 write_unlock(&fscheck_lock);
#endif
#endif 

#if defined(USE_CHECKSUM)
  sm_check_ktext_integrity();
#endif

  return init_module_return;

}
void sm_init_module_end ( void )
{ return; }

