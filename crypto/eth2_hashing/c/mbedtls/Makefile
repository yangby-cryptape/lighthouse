MBEDTLS_VERSION := 4c7eb1131c185cb44d76d43342398882c5c485db
MBEDTLS_URL_PREFIX := https://raw.githubusercontent.com/wolfeidau/mbedtls/${MBEDTLS_VERSION}

MBEDTLS_SRC_FILES := mbedtls/config.h mbedtls/platform.h mbedtls/check_config.h \
					mbedtls/sha256.h source/sha256.c

%.h:
	curl -f -L -o $@ "${MBEDTLS_URL_PREFIX}/$@"

%.c:
	curl -f -L -o $@ "${MBEDTLS_URL_PREFIX}/$@"

.PHONY: download
download: ${MBEDTLS_SRC_FILES}

.PHONY: clean
clean:
	rm -f */*.h */*.c
