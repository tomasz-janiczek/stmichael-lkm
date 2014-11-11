include src/Makefile.in

all:
	(cd src; make)

clean:
	(cd src; make clean)

veryclean:
	(cd src; make veryclean)

dist:   src/Makefile.in
	(cd src; make veryclean)
	chmod -R g-rwx,o-rwx ./
	(cd ..;tar -cz --exclude CVS -f StMichael_LKM-$(VERSION).tar.gz StMichael_LKM-$(VERSION);md5sum StMichael_LKM-$(VERSION).tar.gz > StMichael_LKM-$(VERSION).tar.gz.md5sum;gpg --detach-sign StMichael_LKM-$(VERSION).tar.gz)
	ls -l ../StMichael_LKM-$(VERSION).*
