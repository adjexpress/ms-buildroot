################################################################################
#
# python-fusepy
#
################################################################################

PYTHON_FUSEPY_VERSION = 3.0.1 
PYTHON_FUSEPY_SOURCE = fusepy-$(PYTHON_FUSEPY_VERSION).tar.gz
PYTHON_FUSEPY_SITE = https://files.pythonhosted.org/packages/04/0b/4506cb2e831cea4b0214d3625430e921faaa05a7fb520458c75a2dbd2152
PYTHON_FUSEPY_SETUP_TYPE = setuptools
# PYTHON_FUSEPY_SETUP_TYPE = hatch
PYTHON_FUSEPY_LICENSE = BSD-3-Clause
# PYTHON_FUSEPY_LICENSE_FILES = LICENSE.txt

PYTHON_FUSEPY_DEPENDENCIES = libfuse

$(eval $(python-package))
