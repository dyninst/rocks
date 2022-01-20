include make.config

VERSION = 2.4
CFLAGS   += -fpic
LD_FLAGS += 

SRCS = flight.c ring.c rs.c rserrno.c reconnect.c \
       rw.c hb.c sys.c util.c signal.c select.c   \
       sockopt.c log.c options.c iop.c refun.c \
       shm.c fork.c exec.c 1of2.c
HS   = rs.h log.h flight.h ring.h
DOC  = README INSTALL CHANGES COPYING rock.1 rock.man
MISC = Makefile make.config init.c rock.c rockd.c
MISC2 = COPYING.openssl
BINARIES = librocks.so rock rockd

all: $(BINARIES)

ifdef USE_CRYPTO
 SRCS += crypt.c crypt-openssl.c
 ifdef OPENSSL_INCLUDE_DIR
  CFLAGS += -I$(OPENSSL_INCLUDE_DIR)
 endif
 ifdef OPENSSL_LIBRARY_DIR
  LDFLAGS += -L$(OPENSSL_LIBRARY_DIR)
 endif
 LDFLAGS += -lcrypto
else
 CFLAGS += -DNO_AUTH
endif

OBJS = $(SRCS:.c=.o)
-include depend

.c.o:
	$(CC) $(CFLAGS) -c $<

librocks.so: init.o $(OBJS)
	$(LD) -shared -nostartfiles -o librocks.so $^ $(LDFLAGS) -ldl

rockd: rockd.o $(OBJS)
	$(LD) -o rockd rockd.o $(OBJS) $(LDFLAGS) -ldl

rock.o: rock.c
	$(CC) $(CFLAGS) -D ROCKS_LIB_PATH=\"$(INSTALL_LIB_DIR)\" -c $<

rock: rock.o
	$(LD) -o rock rock.o

rock.man: rock.1
	nroff -man rock.1 > rock.man

clean:
	rm -f core *~ $(OBJS) rockd.o rock.o init.o *.rsync

depend:
	gcc $(INC) -MM $(SRCS) > depend

distclean: clean
	rm -f depend

tarball: $(BINARIES) rock.man
	mkdir rocks-$(VERSION)-linux
	ln $(BINARIES) $(DOC) $(MISC2) rocks-$(VERSION)-linux
	tar zcf rocks-$(VERSION)-linux.tar.gz rocks-$(VERSION)-linux
	rm -rf rocks-$(VERSION)-linux
	mkdir rocks-$(VERSION)
	ln $(SRCS) $(DOC) $(MISC) $(HS) rocks-$(VERSION)
	tar zcf rocks-$(VERSION).tar.gz rocks-$(VERSION)
	rm -rf rocks-$(VERSION)

install: all
	install rock $(INSTALL_BIN_DIR)/rock
	install rockd $(INSTALL_BIN_DIR)/rockd
	install librocks.so $(INSTALL_LIB_DIR)/librocks.so
