#
# Configuration options for building are stored in the Makefile.in file.
# This file is generated by running the ./configure script.
#
# 

include Makefile.in
#DFLAGS	= 
INCLUDESDIR=../includes
OBJSDIR=../objs
CFLAGS = -O3 -I $(INCLUDESDIR)
#
# The Objects...
#
OBJS	= $(OBJSDIR)/StMichael_lkm.o\
$(OBJSDIR)/StMichael_string_util.o\
$(OBJSDIR)/StMichael_timer.o\
$(OBJSDIR)/StMichael_syscall_delete_module_wrapper.o\
$(OBJSDIR)/StMichael_syscall_create_module_wrapper.o\
$(OBJSDIR)/StMichael_syscall_init_module_wrapper.o\
$(OBJSDIR)/StMichael_syscall_exit_wrapper.o\
$(OBJSDIR)/StMichael_integrity_check.o\
$(OBJSDIR)/StMichael_filesystem_check.o\
$(OBJSDIR)/StMichael_mbr_check.o\
$(OBJSDIR)/md5.o\
$(OBJSDIR)/sha1.o



all:  StMichael.o Makefile.in

Makefile.in:
	#   
	# StMichael_LKM Configuration Not Found.
	#   
	# Run the Configure Script First:
	# ./configure	
	#   
	#   
	#   
	# Aborting Compile...
	#    
	/bin/false 

StMichael.o: $(OBJS) 
	ld -o ../bin/StMichael.o -r $(OBJS)
	#
	#
	#
	# To activate Saint Michael, Load the module "StMichael.o" via /sbin/insmod.
	#
	#
	#

$(OBJSDIR)/StMichael_lkm.o:  $(INCLUDESDIR)/StMichael_lkm.h  $(INCLUDESDIR)/StMichael_string_util.h $(INCLUDESDIR)/StMichael_timer.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) $(MFLAGS) -o $(OBJSDIR)/StMichael_lkm.o -c StMichael_lkm.c

$(OBJSDIR)/StMichael_string_util.o:  $(INCLUDESDIR)/StMichael_lkm.h  $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) -DKEY=$$$$ $(MD5FLAGS) -o $(OBJSDIR)/StMichael_string_util.o -c StMichael_string_util.c

$(OBJSDIR)/StMichael_timer.o:  $(INCLUDESDIR)/StMichael_lkm.h $(INCLUDESDIR)/StMichael_timer.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_timer.o -c StMichael_timer.c

$(OBJSDIR)/StMichael_integrity_check.o:  $(INCLUDESDIR)/StMichael_lkm.h  $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_integrity_check.o -c StMichael_integrity_check.c

$(OBJSDIR)/StMichael_filesystem_check.o:  $(INCLUDESDIR)/StMichael_lkm.h  $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_filesystem_check.o -c StMichael_filesystem_check.c

$(OBJSDIR)/StMichael_mbr_check.o: $(INCLUDESDIR)/StMichael_mbr.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_mbr_check.o -c StMichael_mbr_check.c

$(OBJSDIR)/StMichael_syscall_init_module_wrapper.o:  $(INCLUDESDIR)/StMichael_lkm.h $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_syscall_init_module_wrapper.o -c StMichael_syscall_init_module_wrapper.c

$(OBJSDIR)/StMichael_syscall_create_module_wrapper.o:  $(INCLUDESDIR)/StMichael_lkm.h $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_syscall_create_module_wrapper.o -c StMichael_syscall_create_module_wrapper.c

$(OBJSDIR)/StMichael_syscall_exit_wrapper.o:  $(INCLUDESDIR)/StMichael_lkm.h $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_syscall_exit_wrapper.o -c StMichael_syscall_exit_wrapper.c

$(OBJSDIR)/StMichael_syscall_delete_module_wrapper.o:  $(INCLUDESDIR)/StMichael_lkm.h $(INCLUDESDIR)/StMichael_string_util.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) $(CLOAKFLAGS) $(MD5FLAGS) -o $(OBJSDIR)/StMichael_syscall_delete_module_wrapper.o -c StMichael_syscall_delete_module_wrapper.c

$(OBJSDIR)/md5.o:  $(INCLUDESDIR)/md5.h $(INCLUDESDIR)/StMichael_lkm.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) -o $(OBJSDIR)/md5.o -c md5.c

$(OBJSDIR)/sha1.o:  $(INCLUDESDIR)/sha1.h $(INCLUDESDIR)/StMichael_lkm.h
	$(CC) $(CFLAGS) $(IFLAGS) $(DFLAGS) -o $(OBJSDIR)/sha1.o -c sha1.c

clean: 
	rm -f $(OBJS) ../bin/StMichael.o

veryclean: 
	rm -f $(OBJS) ../bin/StMichael.o
	rm -f Makefile.in

dist:   Makefile.in 
	rm -f $(OBJS) ../bin/StMichael.o Makefile.in *~
	mkdir ../StMichael_LKM-$(VERSION)
	cp -a ../stmichael_lkm/* ../StMichael_LKM-$(VERSION)
	chmod -R g-rwx,o-rwx ../StMichael_LKM-$(VERSION)
	(cd ..;tar -c --exclude CVS --exclude TODO -zf StMichael_LKM-$(VERSION).tar.gz StMichael_LKM-$(VERSION);md5sum StMichael_LKM-$(VERSION).tar.gz > StMichael_LKM-$(VERSION).tar.gz.md5sum;gpg --detach-sign StMichael_LKM-$(VERSION).tar.gz)
	ls -l ../StMichael_LKM-$(VERSION).*
