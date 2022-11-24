BITCOIN_VERSION := 38d06e1561013f4ca845fd5ba6ffcc64de67f9c0
BITCOIN_URL_PREFIX := https://raw.githubusercontent.com/bitcoin/bitcoin/${BITCOIN_VERSION}/src/secp256k1/src

BITCOIN_SRC_FILES := util.h hash.h hash_impl.c

%.h:
	curl -f -L -o $@ "${BITCOIN_URL_PREFIX}/$@"

hash_impl.c:
	curl -f -L -o $@ "${BITCOIN_URL_PREFIX}/hash_impl.h"

.PHONY: download
download: ${BITCOIN_SRC_FILES}
	for func in initialize write finalize; do \
		sed -i "s/^static\s\+\(void\s\+secp256k1_sha256_$${func}(.*\)$$/\1/g" hash.h hash_impl.c; \
	done

.PHONY: clean
clean:
	rm -f *.h *.c
