EXTRA_DIST = aerod.man
DISTCLEANFILES = aerod.8 aerod.8.html

man_MANS = aerod.8

all: aerod.8
html: aerod.8.html

MAN_SUBSTS = \
	-e 's|__version__|"$(PACKAGE)-$(VERSION)"|'

aerod.8: aerod.man
	sed $(MAN_SUBSTS) < $< > $@

aerod.8.html: aerod.8
	man2html aerod.8 > aerod.8.html

clean:
	rm -f aerod.8 aerod.8.html
