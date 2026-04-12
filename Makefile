CC       = gcc
CFLAGS   = -Wall -O2 -fPIC -fvisibility=hidden -Ilib -Iinclude
LDFLAGS  = -shared

BUILDDIR = build
LIB      = $(BUILDDIR)/libkcmvp_crypto.so

LIB_SRCS = lib/KCMVP_Crypto.c lib/aria.c lib/aria_Mode.c \
           lib/sha3.c lib/KISA_HMAC_SHA3.c

.PHONY: all clean

all: $(LIB) $(BUILDDIR)/main $(BUILDDIR)/sha3_vs

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(LIB): $(LIB_SRCS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/main: app/main.c app/kat.c $(LIB) | $(BUILDDIR)
	$(CC) -Wall -O2 -Iinclude -Iapp \
	      -L$(BUILDDIR) -Wl,-rpath,'$$ORIGIN' \
	      -o $@ app/main.c app/kat.c -lkcmvp_crypto

$(BUILDDIR)/sha3_vs: test/sha3_vs.c $(LIB) | $(BUILDDIR)
	$(CC) -Wall -O2 -Iinclude \
	      -L$(BUILDDIR) -Wl,-rpath,'$$ORIGIN' \
	      -o $@ test/sha3_vs.c -lkcmvp_crypto

clean:
	rm -rf $(BUILDDIR)
