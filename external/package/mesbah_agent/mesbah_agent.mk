################################################################################
#
# mesbah_agent
#
################################################################################

MESBAH_AGENT_VERSION = 1.0
# MESBAH_AGENT_SOURCE = mesbah_agent-$(MESBAH_AGENT_VERSION).tar.gz
MESBAH_AGENT_SITE = $(MESBAH_AGENT_PKGDIR)/source
MESBAH_AGENT_SITE_METHOD = local
MESBAH_AGENT_LICENSE = GPL-3.0+
MESBAH_AGENT_LICENSE_FILES = COPYING
# MESBAH_AGENT_INSTALL_STAGING = YES
MESBAH_AGENT_INSTALL_TARGET = YES
# MESBAH_AGENT_CONFIG_SCRIPTS = MESBAH_AGENT-config
MESBAH_AGENT_DEPENDENCIES = libopenssl
MESBAH_AGENT_CONF_OPTS =-DBUILD_DEMOS=ON


define MESBAH_AGENT_INSTALL_TARGET_CMDS
$(INSTALL) -D -m 0755 $(@D)/mesbah_agent $(TARGET_DIR)/opt/target
endef


$(eval $(cmake-package))

