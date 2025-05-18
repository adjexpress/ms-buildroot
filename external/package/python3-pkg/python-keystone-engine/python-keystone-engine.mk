################################################################################
#
# python-keystone-engine
#
################################################################################

PYTHON_KEYSTONE_ENGINE_VERSION = 0.9.2
PYTHON_KEYSTONE_ENGINE_SOURCE = keystone-engine-$(PYTHON_KEYSTONE_ENGINE_VERSION).tar.gz
PYTHON_KEYSTONE_ENGINE_SITE = https://files.pythonhosted.org/packages/0a/65/3a2e7e55cc1db188869bbbacee60036828330e0ce57fc5f05a3167ab4b4d
PYTHON_KEYSTONE_ENGINE_SETUP_TYPE = setuptools
# PYTHON_KEYSTONE_ENGINE_SETUP_TYPE = hatch
PYTHON_KEYSTONE_ENGINE_LICENSE = BSD-3-Clause
# PYTHON_KEYSTONE_ENGINE_LICENSE_FILES = LICENSE.txt

PYTHON_KEYSTONE_ENGINE_DEPENDENCIES = host-python

$(eval $(python-package))
