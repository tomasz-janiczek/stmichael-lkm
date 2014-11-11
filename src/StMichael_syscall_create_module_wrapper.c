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


void sm_kmem_rw(void);
void sm_kmem_ro(void);
void sm_mem_rw(void);
void sm_mem_ro(void);

asmlinkage unsigned long
sm_create_module (const char *name, size_t size)
{
  int sm_res;

  /*
  * We can not lock the kernel across a wrapped systemcall
  */
#ifdef ROKMEM
  sm_kmem_rw();
#endif
#ifdef ROMEM
  sm_mem_rw();
#endif
  sm_res = orig_create_module(name,size);
#ifdef ROKMEM
  sm_kmem_ro();
#endif
#ifdef ROMEM
  sm_mem_ro();
#endif

  if (sm_res)
    sm_add_module_list();

  return sm_res;

}

void sm_create_module_end ( void )
{ return;}



