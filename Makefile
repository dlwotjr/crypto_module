CC       = gcc
CFLAGS   = -Wall -O2 -fPIC -fvisibility=hidden -Ilib -Iinclude \
           -Ithird_party/micro-ecc -Ithird_party/PQClean/common \
           -Ithird_party/PQClean/crypto_kem/ml-kem-768/clean
LDFLAGS  = -shared -Wl,--version-script=lib/kcmvp.map
UECC_FLAGS = -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 \
             -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256r1=1 \
             -DuECC_SUPPORTS_secp256k1=0 -DuECC_SUPPORT_COMPRESSED_POINT=0
MLKEM_DIR = third_party/PQClean/crypto_kem/ml-kem-768/clean
MLKEM_SRCS = third_party/PQClean/common/fips202.c \
             $(MLKEM_DIR)/cbd.c $(MLKEM_DIR)/indcpa.c $(MLKEM_DIR)/kem.c \
             $(MLKEM_DIR)/ntt.c $(MLKEM_DIR)/poly.c $(MLKEM_DIR)/polyvec.c \
             $(MLKEM_DIR)/reduce.c $(MLKEM_DIR)/symmetric-shake.c \
             $(MLKEM_DIR)/verify.c

BUILDDIR = build
LIB      = $(BUILDDIR)/libkcmvp_crypto.so
MANIFEST = lib/integrity_manifest.h
MANIFEST_TOOL = $(BUILDDIR)/generate_integrity_manifest

LIB_SRCS = lib/KCMVP_Crypto.c lib/module_state.c lib/selftest.c lib/integrity.c \
           lib/entropy.c \
           lib/hash_drbg.c \
           lib/ecc.c third_party/micro-ecc/uECC.c \
           lib/mlkem.c lib/mlkem_randombytes.c $(MLKEM_SRCS) \
           lib/aria.c lib/aria_Mode.c \
           lib/sha3.c lib/KISA_HMAC_SHA3.c
MANIFEST_INPUTS = lib/KCMVP_Crypto.c lib/module_state.c lib/selftest.c \
                  lib/integrity.c lib/entropy.c lib/hash_drbg.c \
                  lib/ecc.c third_party/micro-ecc/uECC.c \
                  lib/mlkem.c lib/mlkem_randombytes.c $(MLKEM_SRCS) \
                  lib/aria.c lib/aria.h lib/aria_Mode.c \
                  lib/sha3.c lib/KISA_HMAC_SHA3.c

.PHONY: all clean

all: $(LIB) $(BUILDDIR)/main $(BUILDDIR)/sha3_vs $(BUILDDIR)/module_state_test

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(MANIFEST_TOOL): tools/generate_integrity_manifest.c lib/sha3.c lib/sha3.h | $(BUILDDIR)
	$(CC) -Wall -O2 -Ilib -o $@ tools/generate_integrity_manifest.c lib/sha3.c

$(MANIFEST): $(MANIFEST_TOOL) $(MANIFEST_INPUTS)
	./$(MANIFEST_TOOL) $@

$(LIB): $(LIB_SRCS) $(MANIFEST) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(UECC_FLAGS) $(LDFLAGS) -o $@ $(LIB_SRCS)

$(BUILDDIR)/main: app/main.c app/kat.c $(LIB) | $(BUILDDIR)
	$(CC) -Wall -O2 -Iinclude -Iapp \
	      -L$(BUILDDIR) -Wl,-rpath,'$$ORIGIN' \
	      -o $@ app/main.c app/kat.c -lkcmvp_crypto

$(BUILDDIR)/sha3_vs: test/sha3_vs.c $(LIB) | $(BUILDDIR)
	$(CC) -Wall -O2 -Iinclude \
	      -L$(BUILDDIR) -Wl,-rpath,'$$ORIGIN' \
	      -o $@ test/sha3_vs.c -lkcmvp_crypto

$(BUILDDIR)/module_state_test: test/module_state_test.c $(LIB_SRCS) $(MANIFEST) | $(BUILDDIR)
	$(CC) -Wall -O2 -DKCMVP_SELFTEST_TESTING -DKCMVP_INTEGRITY_TESTING \
	      -DKCMVP_ENTROPY_TESTING -DKCMVP_ECC_TESTING \
	      -DKCMVP_MLKEM_TESTING $(UECC_FLAGS) \
	      -Ilib -Iinclude -Ithird_party/micro-ecc \
	      -Ithird_party/PQClean/common -I$(MLKEM_DIR) \
	      -o $@ test/module_state_test.c $(LIB_SRCS)

.PHONY: test audit-exports audit
test: all
	./$(BUILDDIR)/module_state_test
	./$(BUILDDIR)/main --vectors
	./$(BUILDDIR)/sha3_vs

audit-exports: $(LIB)
	@unexpected=$$(nm -D --defined-only $(LIB) | awk '$$2 != "A" && $$3 !~ /^KCMVP_/ { print $$3 }'); \
	if [ -n "$$unexpected" ]; then \
		echo "Unexpected exported symbols:"; echo "$$unexpected"; exit 1; \
	fi
	@echo "Export audit: only KCMVP_* service symbols are exported"

audit: test audit-exports

clean:
	rm -rf $(BUILDDIR)
