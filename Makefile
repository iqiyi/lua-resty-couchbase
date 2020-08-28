OPENRESTY_PREFIX=/usr/local/openresty
INSTALL ?= install
OPM=opm
LUAROCKS=luarockss
TOKEN=

.PHONY: all test install

all: ;

install: all
	$(INSTALL) -d $(OPENRESTY_PREFIX)/lualib
	$(INSTALL) lib/resty/*.lua $(OPENRESTY_PREFIX)/lualib/resty

test: all
	$(OPENRESTY_PREFIX)/bin/resty --http-include $(CURDIR)/t/ldict.conf $(CURDIR)/t/test.lua

opm: all
	$(OPM) build
	$(OPM) upload

luarocks: all
	$(LUAROCKS) upload lua-resty-couchbase-0.3-1.rockspec --api-key=$(TOKEN)