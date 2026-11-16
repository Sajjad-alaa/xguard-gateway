#!/bin/sh
CONFIG=/etc/xguard/gateway.toml

if [ ! -f "${CONFIG}" ]; then
	cp "${CONFIG}.sample" "${CONFIG}"
fi
