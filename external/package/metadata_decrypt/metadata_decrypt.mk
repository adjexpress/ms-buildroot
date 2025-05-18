################################################################################
#
# metadata_decrypt
#
################################################################################

METADATA_DECRYPT_VERSION = 1.0
METADATA_DECRYPT_SITE = $(METADATA_DECRYPT_PKGDIR)/source
METADATA_DECRYPT_SITE_METHOD = local
METADATA_DECRYPT_LICENSE = GPL-3.0+
METADATA_DECRYPT_LICENSE_FILES = COPYING
# METADATA_DECRYPT_INSTALL_STAGING = YES
METADATA_DECRYPT_INSTALL_TARGET = YES
# METADATA_DECRYPT_CONFIG_SCRIPTS = METADATA_DECRYPT-config
# METADATA_DECRYPT_DEPENDENCIES = libopenssl
METADATA_DECRYPT_CONF_OPTS =-DBUILD_DEMOS=ON


define METADATA_DECRYPT_INSTALL_TARGET_CMDS
$(INSTALL) -D -m 0755 $(@D)/meta_data_crypt $(TARGET_DIR)/usr/bin/
endef


$(eval $(cmake-package))

