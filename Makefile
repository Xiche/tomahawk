#
#  Makefile for Tomahawk Tools
#
#  bsmith@netpliance.net
#

PREFIX		= /usr/local
BINDIR		= $(PREFIX)/bin
MANDIR		= $(PREFIX)/man/man8

CC		= gcc
#CFLAGS		= -g -pipe -Wall
#CFLAGS		= -g -pipe -Wall -DMEM_DEBUG -DMEM_VALIDATE
#CFLAGS		= -g -pipe -Wall -DDEBUG_STACK -DVALIDATE_HEAP -DMEM_VALIDATE -DMEM_DEBUG
#CFLAGS		= -pg -O2 -pipe -Wall -funroll-loops -DNDEBUG
CFLAGS		= -O2 -pipe -Wall -funroll-loops -fomit-frame-pointer -DNDEBUG
LDFLAGS		=
DEFS		= -DHAVE_CONFIG_H
INCS		= $(LNETINCS) $(PCAPINCS)
# LIBS		= -lnsl  $(LNETLIBS) $(PCAPLIBS)
LIBS		= -lnsl $(PCAPLIBS)

INSTALL		= /usr/bin/install -c -p
INSTALL_PROGRAM	= ${INSTALL}
RM              = /bin/rm -f
MKDIR           = /bin/mkdir -p

PCAPDIR		= ../libpcap-0.8.1
PCAPINCS	= -I$(PCAPDIR)
PCAPLIBS	= $(PCAPDIR)/libpcap.a
PCAPDEP		= $(PCAPDIR)/pcap.h $(PCAPDIR)/libpcap.a

LNETDIR		= ../Libnet-1.0.2a
LNETINCS	= -I$(LNETDIR)/include
LNETLIBS	= $(LNETDIR)/lib/libnet.a
LNETDEP		= $(LNETDIR)/include/libnet.h $(LNETDIR)/libnet.a

FILES           = tomahawk

PROGRAMS	= tomahawk

all: $(PROGRAMS)

tags: tomahawk.c alloc.c eventloop.c eventloop.h packetutil.c packetutil.h
	ctags tomahawk.c alloc.c eventloop.c eventloop.h packetutil.c packetutil.h

tomahawk: tomahawk.c alloc.c eventloop.c eventloop.h packetutil.c packetutil.h Makefile
	-rm -f tomahawk
	$(CC) $(CFLAGS) $(DEFS) $(INCS) `$(LNETDIR)/libnet-config --defines` -o $@ tomahawk.c eventloop.c packetutil.c alloc.c $(LDFLAGS) $(LIBS)

$(PCAPDIR)/libpcap.a:
	cd $(PCAPDIR) ; $(MAKE)

$(LNETDIR)/libnet.a:
	cd $(LNETDIR) ; $(MAKE)

clean:
	cd $(PCAPDIR) ; $(MAKE) clean
	cd $(LNETDIR) ; $(MAKE) clean
	rm -f *~ *.o *core $(PROGRAMS)

distclean: clean
	cd $(PCAPDIR) ; $(MAKE) distclean
	cd $(LNETDIR) ; $(MAKE) distclean
	rm -f Makefile config.h config.status config.cache config.log

install:
	$(MKDIR) $(BINDIR)
	for file in $(FILES); do \
	  $(INSTALL) -m 755 $$file $(BINDIR); \
	done

uninstall:
	for file in $(FILES); do \
	  $(RM) $(BINDIR)/$$file; \
	done

