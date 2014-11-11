/* Saint Michael, Linux Kernel Module -> mbr checks
 * Verions: 0.12
 *
 * October 22, 2005
 *
 *
 *    Copyright (C) 2005  Rodrigo Rubira Branco (rodrigo@kernelhacking.com)
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>     /* functions inb(), outb() - StMichael_mbr_check.c */
#include <linux/delay.h> /* macro ndelay() */
#include "StMichael_mbr.h"


#ifdef MBRCHECK

/*
Return value:
	0  - Sucess
	>0 - Error code
*/
int mbr_read( short *inbuf )
{
	int		timeout, status, error, i;	
	
	timeout = 1000;

	do	
	{
		status = inb( IDE_STATUS );
		if ( (status & 0x88 ) == 0x00 ) 	
			break;
	} while ( --timeout );

	if ( ! timeout ) 
		return -EBUSY;

	outb( 0xE0, IDE_DEVICE );	// master disk, LBA addressing
	ndelay( 400 );			// delay for 400 nanoseconds

	status = inb( IDE_STATUS );
	if ( unlikely((status & 0xC8 ) != 0x40 )) 
		return -EFAULT;

	outb( 1, IDE_SECTOR_COUNT );
	outb( 0, IDE_SECTOR_LOW );
	outb( 0, IDE_SECTOR_MID ); 	
	outb( 0, IDE_SECTOR_HIGH ); 	
	outb( 0xE0, IDE_DEVICE );
	outb( CMD_READ_SECTOR, IDE_COMMAND );

	error = 0;		
	ndelay( 400 );			// delay for 400 nanoseconds	
	status = inb( IDE_STATUS );	// was any error info posted?

	if ( (status & 0x81) == 0x01 ) 
	{
		error = inb( IDE_ERROR );
		return	error;
	}

	timeout = 1000000;
	do	
	{
		status = inb( IDE_STATUS );
		if ( (status & 0x88) == 0x08 ) 
			break;
	} while ( --timeout );

	if ( ! timeout ) 
		return -EFAULT;	

	for (i = 0; i < 256; i++) 
		inbuf[i] = inw( IDE_DATA );

	status = inb( IDE_STATUS );
	return	0;  //SUCCESS			
}
#endif
