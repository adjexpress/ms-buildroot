################################################################################
#
# teegris_kdf
#
################################################################################

TEEGRISKDF_VERSION = 1.0
TEEGRISKDF_SITE = $(TEEGRISKDF_PKGDIR)/source
TEEGRISKDF_SITE_METHOD = local
TEEGRISKDF_LICENSE = GPL-3.0+
TEEGRISKDF_LICENSE_FILES = COPYING
# TEEGRISKDF_INSTALL_STAGING = YES
TEEGRISKDF_INSTALL_TARGET = YES
# TEEGRISKDF_CONFIG_SCRIPTS = TEEGRISKDF-config
TEEGRISKDF_DEPENDENCIES = libopenssl
TEEGRISKDF_CONF_OPTS =-DBUILD_DEMOS=ON


define TEEGRISKDF_INSTALL_TARGET_CMDS
$(INSTALL) -D -m 0755 $(@D)/TeegrisKDF $(TARGET_DIR)/usr/bin/teegrisKDF
endef


$(eval $(cmake-package))

