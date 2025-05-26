################################################################################
#
# metadata_decrypt
#
################################################################################

FSCRYPT_KEYUTIL_VERSION = 1.0
FSCRYPT_KEYUTIL_SITE = $(FSCRYPT_KEYUTIL_PKGDIR)/src
FSCRYPT_KEYUTIL_SITE_METHOD = local
FSCRYPT_KEYUTIL_LICENSE = GPL-3.0+
FSCRYPT_KEYUTIL_LICENSE_FILES = COPYING
# FSCRYPT_KEYUTIL_INSTALL_STAGING = YES
FSCRYPT_KEYUTIL_INSTALL_TARGET = YES
# FSCRYPT_KEYUTIL_CONFIG_SCRIPTS = FSCRYPT_KEYUTIL-config
FSCRYPT_KEYUTIL_DEPENDENCIES = keyutils
FSCRYPT_KEYUTIL_CONF_OPTS =-DBUILD_DEMOS=ON


define FSCRYPT_KEYUTIL_INSTALL_TARGET_CMDS
$(INSTALL) -D -m 0755 $(@D)/fscrypt_keyutil $(TARGET_DIR)/usr/bin/
endef


$(eval $(cmake-package))

