#DFLAGS	= 
CFLAGS = -O3

#
# Compiler
# In Redhat 7.0 and systems using versions of GCC greater then 2.95, the
# Kernel will not compile... Those systems have a kgcc installed for compiling
# the kernel, which is an older version of the gcc package. On these systems
# it is necessary to use kgcc to compile Stjude also. Compiling StMichael
# with newer versions of GCC may result in faild insmods (undefined symbols)
# or in seemingly random kernel oopses (whatever the plural of oops is).
#
CC	= kgcc
#
# If the above note does not apply to you, or your system is using an older
# GCC, uncoment the following line and comment out the preceeding definition
# of "CC".
#
CC      = gcc

#IFLAGS	= -I/usr/src/linux

 IFLAGS	= -I/lib/modules/`uname -r`/build/include

#
#
# The Objects...

all:	test_attack_syscall_replace.o test_attack_kernel_modify.o test_detect_lkm_cloaking.o test_dead_do_execve.o test_attack_stmichael.o 
	#  
	#
	#    WARNING! WARNING! WARNING! WARNING! WARNING!
	#
	#  Loading these modules without StMichael present can render a
	#  system unusable untill it is manually rebooted.
	#
	#  Any attempt to load the test_attack_kernel_modify.o module
	#  with StMichael loaded will trigger the system reboot defense
	#  and the computer will reboot immediately!!!
	#  
	#  DO NOT RUN THESE TEST MODULES ON A PRODUCTION SERVER IF YOU
	#  NOT AFFORD TO REBOOT IMMEDIATELY AND WAIT WHILE THE SYSTEM
	#  CHECKS THE FILESYSTEMS.
	#
	#    WARNING! WARNING! WARNING! WARNING! WARNING!
	#
test_attack_syscall_replace.o:  test_attack.c 
	$(CC) $(CFLAGS) $(IFLAGS) -DTEST_ONE -o test_attack_syscall_replace.o -c test_attack.c
test_attack_kernel_modify.o:  test_attack.c 
	$(CC) $(CFLAGS) $(IFLAGS) -DTEST_TWO -o test_attack_kernel_modify.o -c test_attack.c
test_detect_lkm_cloaking.o:  test_attack.c 
	$(CC) $(CFLAGS) $(IFLAGS) -DTEST_THREE -o test_detect_lkm_cloaking.o -c test_attack.c
test_dead_do_execve.o:  test_attack.c 
	$(CC) $(CFLAGS) $(IFLAGS) -DTEST_FOUR -o test_dead_do_execve.o -c test_attack.c
test_attack_stmichael.o:  test_attack.c 
	$(CC) $(CFLAGS) $(IFLAGS) -DTEST_FIVE -o test_attack_stmichael.o -c test_attack.c

clean:
	rm -f *.o
