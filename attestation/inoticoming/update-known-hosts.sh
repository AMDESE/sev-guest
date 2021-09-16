#!/bin/bash
#
# The CGI script will populate /var/www/attestation with known_hosts entries for SEV-SNP guests
# that successfully attest. Copy this script to ~/scripts, then configure inoticoming to monitor
# the contents of /var/www/attestation and run this script on any new files:
#
# $ inoticoming /var/www/attestation/ ~/scripts/update-known-hosts.sh /var/www/attestation/\{\} \;

if [ -r "$1" ]; then
	cat $1 >> $HOME/.ssh/known_hosts
fi
