#!/bin/sh

PREREQ=""

prereqs()
{
	echo "$PREREQ"
}

case $1 in
prereqs)
	prereqs
	exit 0
	;;
esac

. /usr/share/initramfs-tools/hook-functions
# Begin real processing below this line

# Add the CCP module for retrieving the attestation report
manual_add_modules ccp

# Add the userspace tool to request the attestation report
copy_exec /usr/bin/sev-guest-get-report

# Add tar and curl to send the report to our attestation server
copy_exec /usr/bin/tar
copy_exec /usr/bin/curl

# Add the CA root certificate for our attestation server
copy_file PEM /usr/local/share/ca-certificates/jlarrew-root-ca-cert.crt

# Add the local build of openssl3
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib64/
copy_exec /usr/local/bin/openssl
