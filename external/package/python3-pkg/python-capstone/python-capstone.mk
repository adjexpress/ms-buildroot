################################################################################
#
# python-capstone
#
################################################################################

PYTHON_CAPSTONE_VERSION = 5.0.5
PYTHON_CAPSTONE_SOURCE = capstone-$(PYTHON_CAPSTONE_VERSION).tar.gz
PYTHON_CAPSTONE_SITE = https://files.pythonhosted.org/packages/a4/23/759da7f13c2ce29ffe90ccb45eb61ffcd310b436bfb489f3dbd11fba8776
PYTHON_CAPSTONE_SETUP_TYPE = setuptools
# PYTHON_CAPSTONE_SETUP_TYPE = hatch
PYTHON_CAPSTONE_LICENSE = BSD-3-Clause
# PYTHON_CAPSTONE_LICENSE_FILES = LICENSE.txt

$(eval $(python-package))
