

/* Saint Michael, Linux Kernel Module.
 * Version: 0.11
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


#include <linux/timer.h>

#define SM_TIMEOUT		3600

void sm_timer_init(void);
void sm_timer_remove(void);
void sm_timer_handler(unsigned long);

// This should not be handeld by configure
//
//#warning If compile fails here read StMichael_timer.h.

// On some systems, particularly redhat boxes, this may cause
// A Problem -- Redhat has had it declared Elsewhere in their 
// 'Patched' Linux Distribution.
// If you encounter this compile time problem, Delete the next line.
//
//
#if !defined(GOT_TIME)
typedef struct timer_list timer_t;
#endif

extern timer_t sm_timer;
