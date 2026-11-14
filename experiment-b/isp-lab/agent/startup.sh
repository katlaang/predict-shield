#!/usr/bin/env bash
set -euo pipefail
: "${LAB_SNMP_AUTH:?missing disposable auth}"
: "${LAB_SNMP_PRIV:?missing disposable privacy}"
: "${LAB_DEVICE_ID:?missing lab device ID}"
if [[ ! "$LAB_DEVICE_ID" =~ ^[a-z0-9-]{1,32}$ ]]; then exit 2; fi
install -d -m 700 /var/lib/snmp
umask 077
printf 'createUser reader SHA "%s" AES "%s"\n' "$LAB_SNMP_AUTH" "$LAB_SNMP_PRIV" > /var/lib/snmp/snmpd.conf
cat > /etc/snmp/snmpd.conf <<EOF
agentAddress udp:161
rouser reader priv .1.3.6.1.2.1.1
sysName $LAB_DEVICE_ID
sysLocation disposable-isp-testbed
EOF
unset LAB_SNMP_AUTH LAB_SNMP_PRIV
exec /usr/sbin/snmpd -f -Lo
