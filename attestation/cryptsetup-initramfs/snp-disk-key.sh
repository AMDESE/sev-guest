#!/bin/sh

#set -x

DISK_KEY_URL="http://sev-repo.multipass/cgi-bin/disk-key.sh"

stderr()
{
	echo "${@}" > /dev/stderr
}

die()
{
	stderr "ERROR: ${@}"
	exit 1
}

is_virtual_machine()
{
	dmesg | grep "Detected virtualization kvm" > /dev/null
}

send_report()
{
	local report=${1}
	curl --data-binary @${report} -H "Content-Type: application/octet-stream" ${DISK_KEY_URL}
}

derive_key()
{
	local label=${1}
	local bits=${2}

	local bytes=$(( bits/8 ))
	local input_key=derived-key
	local input_key_b64=${input_key}.b64

	# Ask the ASP to derive a key from the guest VM Root Key.
	# This key migrates with the guest, so it is suitable as
	# key material for the derivation of sub-keys.
	if [ ! -r "${input_key}" ]; then
		sev-guest-kdf -r ${input_key} > /dev/null
		openssl base64 -in ${input_key} -out ${input_key_b64}
	fi

	openssl kdf -mac hmac -digest sha256 -kdfopt info:${label} \
		    -kdfopt key:$(cat ${input_key_b64}) -keylen ${bytes} SSKDF | \
		sed -e 's/://g'
}

verify_hmac()
{
	local valid_hmac=${1}
	local input_file=${2}

	if [ ! -r integrity-key ]; then
		derive_key "integrity-key" 256 > integrity-key
	fi

	local hmac=$(openssl dgst -sha512 -hmac "$(cat integrity-key)" ${input_file} | cut -d ' ' -f 2)

	[ "${valid_hmac}" = "${hmac}" ]
}

decrypt()
{
	local encrypted=${1}

	if [ ! -r encryption-key ]; then
		derive_key "encryption-key" 256 > encryption-key
	fi

	openssl enc -d -aes-256-cbc -pass file:encryption-key --pbkdf2 -a < ${encrypted}
}

main()
{
	# Change to a safe temporary directory
	#local work_dir=$(mktemp -d /tmp/$(basename $0)-XXXXXX)
	local work_dir=$(pwd)/work
	local cwd=$(pwd)
	cd ${work_dir}

	if [ ! is_virtual_machine ]; then
		die "not a virtual machine!"
	fi

	# Retrieve the SNP attestation report
	local report=report.bin
	sev-guest-get-report ${report} > /dev/null

	# Send the report to the attestation server
	send_report ${report} > cgi_response

	if grep "Validation failed." cgi_response; then
		die "attestation failed."
	fi

	stderr "Attestation successful!"

	# Extract the encrypted disk key along with the HMAC
	grep -m 1 -w -o "key=[^ ]*" cgi_response | sed -e 's/^key=//' > wrapped_key
	local hmac=$(grep -m 1 -w -o "hmac=[^ ]*" cgi_response | sed -e 's/^hmac=//')

	# Verify the HMAC of the encrypted disk key
	if ! verify_hmac ${hmac} wrapped_key; then
		die "HMAC validation failed!"
	fi

	# Print the decrypted disk key
	decrypt wrapped_key

	# Cleanup
	cd ${cwd}
	#rm -rf ${work_dir}
}

main $@
