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


int
sm_delete_module (const char *name)
{
   int delete_module_return;


   if (name != NULL && *name != '\0')
   {
   if ( ! sjp_l_strncmp(name,"StMichael", 12) )
      {
#if defined(CLOAK)
	 return -ENOENT;
#else
         return -EBUSY;
#endif
      }

   if ( ! sjp_l_strncmp(name,"+",1) )
      {
        return -EBUSY;
      }
    }

#if defined(FSCHECK) && defined(USE_CHECKSUM)
#ifdef __SMP__
 write_lock(&fscheck_lock);
#endif
 check_fscheck_records();
#ifdef __SMP__
 write_unlock(&fscheck_lock);
#endif
#endif

   delete_module_return = (*orig_delete_module)(name);
   
  /* 
     Verify that the syscall table is the same. 
     If its changed then respond 

     We could probably make this a function in itself, but
     why spend the extra time making a call?

   */

#ifdef USE_CHECKSUM
   sm_check_dependency_integrity();
#endif

   if (delete_module_return == 0)
   	sm_remove_module_list(name);

   sm_check_sys_call_integrity();

   sm_check_module_list();
#ifdef USE_CHECKSUM
   sm_check_ktext_integrity ();
#endif


  return delete_module_return;

}

void sm_delete_module_end (void)
{ return; }

