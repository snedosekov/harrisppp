##############################################
# OpenWrt Makefile for helloworld program
#
#
# Most of the variables used here are defined in
# the include directives below. We just need to 
# specify a basic description of the package, 
# where to build our program, where to find 
# the source files, and where to install the 
# compiled program on the router. 
# 
# Be very careful of spacing in this file.
# Indents should be tabs, not spaces, and 
# there should be no trailing whitespace in
# lines that are not commented.
# 
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=harrisppp
PKG_RELEASE:=1
PKG_SOURCE:=harrisppp.tar.gz

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/harrisppp
    SECTION:=base
    CATEGORY:=Network
    DEFAULT:=y
    TITLE:=Harris Falkon II PPP driver
    DEPENDS+= +libopenssl +kmod-tun
endef

define Package/harrisppp/description
    Driver for PPP Harris Falkon II radio station
    privide IP tunnel.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/conffiles
/etc/harrisppp/ppp.conf
/etc/harrisppp/ppp.linkup
/etc/harrisppp/ppp.linkdown
endef

define Build/Configure
$(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

define Package/harrisppp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/harrisppp $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/harrisppp/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/ppp.conf $(1)/etc/harrisppp/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/ppp.linkup $(1)/etc/harrisppp/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/ppp.linkdown $(1)/etc/harrisppp/
endef

$(eval $(call BuildPackage,harrisppp))