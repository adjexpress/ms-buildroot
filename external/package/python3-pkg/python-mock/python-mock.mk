################################################################################
#
# python-mock
#
################################################################################

PYTHON_MOCK_VERSION = 5.1.0 
PYTHON_MOCK_SOURCE = mock-$(PYTHON_MOCK_VERSION).tar.gz
PYTHON_MOCK_SITE = https://files.pythonhosted.org/packages/66/ab/41d09a46985ead5839d8be987acda54b5bb93f713b3969cc0be4f81c455b
PYTHON_MOCK_SETUP_TYPE = setuptools
# PYTHON_MOCK_SETUP_TYPE = hatch
PYTHON_MOCK_LICENSE = BSD-3-Clause
# PYTHON_MOCK_LICENSE_FILES = LICENSE.txt

$(eval $(python-package))
