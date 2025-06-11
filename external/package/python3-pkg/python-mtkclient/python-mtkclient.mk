################################################################################
#
# python-mtkclient
#
################################################################################

PYTHON_MTKCLIENT_VERSION = 2.0.1
# PYTHON_MTKCLIENT_SOURCE = mtkclient-$(PYTHON_MTKCLIENT_VERSION).tar.gz
PYTHON_MTKCLIENT_SITE = $(PYTHON_MTKCLIENT_PKGDIR)/src
PYTHON_MTKCLIENT_SITE_METHOD = local
PYTHON_MTKCLIENT_SETUP_TYPE = setuptools
PYTHON_MTKCLIENT_LICENSE = GPLv3

# PYTHON_MTKCLIENT_DEPENDENCIES = 

$(eval $(python-package))
