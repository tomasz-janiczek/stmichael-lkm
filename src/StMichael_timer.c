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
#include <linux/timer.h>
#include "StMichael_lkm.h"
#include "StMichael_timer.h"
#include "md5.h"

timer_t sm_i_timer;

#include "StMichael_string_util.h"

timer_t sm_timer;

md5_byte_t int_digest[8][16];

extern SM_INTEGRITY_RECORD *recorded_dependency_table;

ssize_t sj_deny_write ( struct file * file, const char * stuff, size_t size, loff_t * loff );
void sm_timer_handler(unsigned long arg);
void sm_i_timer_handler(unsigned long arg);
void sm_fs_end( void );
void sm_int_begin (void);
void sm_int_end (void);
void string_end (void);
void sm_create_module_end (void);
void sm_exit_end (void);
void sm_delete_module_end (void);
void sm_timer_end (void);
void sm_init_module_end (void);
void sm_kmem_ro ( void );
void sm_kmem_rw ( void );

void sm_timer_init(void)
{

#ifdef USE_CHECKSUM
    int i;
    unsigned long start;
    unsigned long len;
    md5_state_t state;
#endif

    sjp_l_memset(&sm_timer,0,sizeof(timer_t));
    init_timer(&sm_timer);
    sm_timer.expires = jiffies + SM_TIMEOUT;
    sm_timer.function = sm_timer_handler;

#ifdef USE_CHECKSUM
    sjp_l_memset(&sm_i_timer,0,sizeof(timer_t));
    init_timer(&sm_i_timer);
    sm_i_timer.expires = jiffies + (SM_TIMEOUT / 2);
    sm_i_timer.function = sm_i_timer_handler;


    for (i = 0; i < 8; i++)
    {
      switch (i) {

	    case 0:
#ifdef REALLY_IMMUTABLE
		    start = (unsigned long) sm_ext2_ioctl;
		    len = ((unsigned long) sm_fs_end) - start;
#endif
		    break;
	    case 1:
		    start = (unsigned long) &sm_int_begin;
		    len = ((unsigned long) sm_int_end) - start;
		    break;
	    case 2:
		    start = (unsigned long) sjp_l_munge_memory;
		    len = ((unsigned long) string_end) - start;
		    break;
	    case 3:
		    start = (unsigned long) sm_create_module;
		    len = ((unsigned long) sm_create_module_end) - start;
		    break;
	    case 4:
		    start = (unsigned long) sm_exit;
		    len = ((unsigned long) sm_exit_end) - start;
		    break;
	    case 5:
		    start = (unsigned long) sm_delete_module;
		    len = ((unsigned long) sm_delete_module_end) - start;
		    break;
	    case 6:
		    start = (unsigned long) sm_init_module;
		    len = ((unsigned long) sm_init_module_end) - start;
		    break;
	    case 7:
		    start = (unsigned long) sm_i_timer_handler;
		    len = ((unsigned long) sm_timer_end) - start;
		    break;

            
            }

 
      md5_init(&state);
      md5_append(&state, (const md5_byte_t *) start, len);
      md5_finish(&state,int_digest[i]);

    }

    add_timer(&sm_i_timer);
#endif
    add_timer(&sm_timer);
}

#ifdef USE_CHECKSUM
void sm_i_timer_handler(unsigned long arg)
{

    unsigned long flags = 0;
    int i;
    unsigned long start;
    unsigned long len;
    md5_state_t state;
    md5_byte_t digest[16];

    del_timer(&sm_i_timer);
    local_irq_save(flags);



    for (i = 0; i < 8; i++)
    {
	    int j;

      switch (i) {

	    case 0:
#ifdef REALLY_IMMUTABLE
		    start = (unsigned long) sm_ext2_ioctl;
		    len = ((unsigned long) sm_fs_end) - start;
#endif
		    break;
	    case 1:
		    start = (unsigned long) sm_int_begin;
		    len = ((unsigned long) sm_int_end) - start;
		    break;
	    case 2:
		    start = (unsigned long) sjp_l_munge_memory;
		    len = ((unsigned long) string_end) - start;
		    break;
	    case 3:
		    start = (unsigned long) sm_create_module;
		    len = ((unsigned long) sm_create_module_end) - start;
		    break;
	    case 4:
		    start = (unsigned long) sm_exit;
		    len = ((unsigned long) sm_exit_end) - start;
		    break;
	    case 5:
		    start = (unsigned long) sm_delete_module;
		    len = ((unsigned long) sm_delete_module_end) - start;
		    break;
	    case 6:
		    start = (unsigned long) sm_init_module;
		    len = ((unsigned long) sm_init_module_end) - start;
		    break;
	    case 7:
		    start = (unsigned long) sm_i_timer_handler;
		    len = ((unsigned long) sm_timer_end) - start;
		    break;

            
            }
      md5_init(&state);
      md5_append(&state, (const md5_byte_t *) start, len);
      md5_finish(&state,digest);

      for (j = 0; j < 16; j++)
	      if (digest[j] != int_digest[i][j])
	      {
                     int flags; 
		     //unsigned long * c;
		     //unsigned long * p;


		     switch (i) {
			case 0:
				goto shit_meet_fan;
			case 1:
			case 2:
repeat_till_dead:
				break;
				while (1)
				{ ; }
				goto repeat_till_dead;

			case 3 :
			case 4 :
			case 5 :
			case 6 :
			case 7 :
shit_meet_fan:
    			       local_irq_restore(flags);
			       machine_restart(NULL);
			       goto repeat_till_dead;
		}
		break;
		
	      }

    }

    local_irq_restore(flags);
    init_timer(&sm_i_timer);
    sm_i_timer.expires = jiffies + (SM_TIMEOUT / 2)
	    + (jiffies % SM_TIMEOUT) + 1;
    sm_i_timer.function = sm_i_timer_handler;
    add_timer(&sm_i_timer);
    return;

}
#endif

void sm_timer_handler(unsigned long arg)
{
    
    unsigned long flags = 0;
   
    local_irq_save(flags);
    del_timer(&sm_timer);

    // A modification of the ktext integrity check that
    // will check only stmichel's integrity. If its fucked,
    // panic the system.

#ifdef USE_CHECKSUM
   sm_check_dependency_integrity();
#endif

   sm_check_sys_call_integrity();
   sm_check_module_list();
#ifdef USE_CHECKSUM
   sm_check_ktext_integrity ();
#endif


    local_irq_restore(flags);
    init_timer(&sm_timer);
    sm_timer.expires = jiffies + SM_TIMEOUT;
    sm_timer.function = sm_timer_handler;
    add_timer(&sm_timer);
}

void sm_timer_end ( void )
{ return; }
