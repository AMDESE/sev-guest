#!/bin/bash
#
#

set -e

KEY_DIR=/var/www/keys

stderr()
{
	echo "${@}" > /dev/stderr
}

die()
{
	stderr "ERROR: ${FUNCNAME[1]}: ${@}"
	exit 1
}

create_key_entry()
{
	local id=${1}
	local key=${2}

	[ -z ${id} ] && die "identity key fingerprint is empty!"
	[ -z ${password} ] && die "password is empty!"

	local entry=${KEY_DIR}/${id}
	local ignore=$(echo -n ${key} | sudo tee ${entry})
	ignore=""

	# Ensure that only the web server can read the keys (but not modify them)
	sudo chown www-data:www-data ${KEY_DIR}/${id}
	sudo chmod og-rwx ${KEY_DIR}/${id}
	sudo chmod u-wx ${KEY_DIR}/${id}

	echo "created new entry in ${entry}"
}

main()
{
	local pubkey=${1}
	local password=""

	[ -z "${pubkey}" ] && die "Identity public key is required."

	local id=$(sev-host-identity -g ${pubkey} | \
			cut -d ' ' -f 3)

	[ -z "${id}" ] && die "fingerprint is empty!"

	echo "public key fingerprint is ${id}"

	read -s -p "Enter the password to associate with this fingerprint:" password
	echo

	create_key_entry ${id} ${password}
}

main $@
