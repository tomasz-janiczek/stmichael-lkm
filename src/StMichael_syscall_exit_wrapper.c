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
#include "StMichael_lkm.h"
#include "StMichael_string_util.h"


int sm_exit (int error)   /* DONE */
{
  int sj_exit_ret;

#ifdef USE_CHECKSUM
 sm_check_dependency_integrity();
#endif

 sm_check_sys_call_integrity();
#if defined(USE_CHECKSUM) 
 sm_check_ktext_integrity ();
#endif

  sj_exit_ret = (*orig_exit) (error);
  return sj_exit_ret;

}

void sm_exit_end ( void )
{ return; }

#ifdef CHECKSUM
md5_byte_t syscall_md5[16];
#endif

