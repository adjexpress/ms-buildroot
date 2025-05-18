###############
# usbip
###############

# No USBIP_SITE, no USB_VERSION, we vampirise the code from the
# linux kernel
USBIP_PATCH_DEPENDENCIES = linux

USBIP_SRC_DIR = $(wildcard \
  $(LINUX_DIR)/tools/usb/usbip \
  $(LINUX_DIR)/drivers/staging/usbip/userspace)

define USBIP_EXTRACT_CMDS
	if [[ -z "$(USBIP_SRC_DIR)" ]]; then \
	    echo "No usbip source in your kernel tree" 2>&1; \
	    exit 1; \
	fi
	rsync -a $(USBIP_SRC_DIR)/ $(@D)
endef

#Running autogen.sh is needed to create configure script.
USBIP_AUTORECONF = YES

ifneq ($(BR2_USBIP_CLIENT),y)
        USBIP_TOREMOVE += usbip
endif
ifneq ($(BR2_USBIP_SERVER),y)
        USBIP_TOREMOVE += usbipd bind_driver
endif

define USBIP_CLEANUP_AFTER_INSTALL
        rm -f $(addprefix $(TARGET_DIR)/usr/bin/, $(USBIP_TOREMOVE))
endef

USBIP_POST_INSTALL_TARGET_HOOKS += USBIP_CLEANUP_AFTER_INSTALL

$(eval $(autotools-package))
