
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


int mbr_read( short *inbuf);

#define IDE_DATA		0x1F0
#define IDE_ERROR		0x1F1
#define IDE_FEATURES		0x1F1
#define IDE_SECTOR_COUNT	0x1F2
#define IDE_SECTOR_LOW	 	0x1F3
#define IDE_SECTOR_MID		0x1F4
#define IDE_SECTOR_HIGH		0x1F5
#define IDE_DEVICE		0x1F6
#define IDE_STATUS		0x1F7
#define IDE_COMMAND 		0x1F7
#define IDE_DEVICE_CONTROL	0x3F6
#define CMD_READ_SECTOR		0x20
#define MBR_LENGTH		512
