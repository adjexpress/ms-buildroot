################################################################################
#
# python-pycryptodom
#
################################################################################

PYTHON_PYCRYPTODOME_VERSION = 3.21.0 
PYTHON_PYCRYPTODOME_SOURCE = pycryptodome-$(PYTHON_PYCRYPTODOME_VERSION).tar.gz
PYTHON_PYCRYPTODOME_SITE = https://files.pythonhosted.org/packages/13/52/13b9db4a913eee948152a079fe58d035bd3d1a519584155da8e786f767e6
PYTHON_PYCRYPTODOME_SETUP_TYPE = setuptools
# PYTHON_PYCRYPTODOME_SETUP_TYPE = hatch
PYTHON_PYCRYPTODOME_LICENSE = BSD-3-Clause
# PYTHON_PYCRYPTODOME_LICENSE_FILES = LICENSE.txt

$(eval $(python-package))
