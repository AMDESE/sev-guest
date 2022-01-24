#!/usr/bin/bash
#
# disk-key.sh
#
# Validate a SEV-SNP guest report and respond with the disk encryption key.
#
# This script requires the directory /var/www/keys to exist and contain files
# named after the ID key hash of each guest. The content of the files must be
# the plaintext disk encryption passphrase without any trailing '\n' character.
#
# e.g.: $ echo -n passphrase > /var/www/keys/000000111111222222333333444444555555666666777777888888999999aaaaaabbbbbbccccccddddddeeeeeeffffff
#
# where 000000111111222222...ffffff is the SHA384 hash of the guest ID key.
#
# To protect the secrecy of the keys, the directory /var/www/keys should be
# readable only by the www-data user. This script will encrypt the passphrase
# before sending it in the CGI response.

set -x

SEV_TOOL=/home/bc/src/git/sev-tool/src/sevtool
LOGFILE=/var/www/cgi.log
KEYS_DIR=/var/www/keys

log()
{
	echo "[$(date --rfc-3339='ns')] $@" >> ${LOGFILE}
}

cgi_response()
{
	local mimetype="text/html"
	local title=$1
	local heading=$2
	local body=$3

	echo "Content-type: ${mimetype}";
	echo
	echo "<HTML>";
	echo "<HEAD><TITLE>${title}</TITLE></HEAD>";
	echo "<BODY>";
	echo "<H1>${heading}</H1><HR>";
	echo "${body}";
	echo "</BODY></HTML>";
}

get_tcb_version()
{
	local report=${1}
	sev-guest-parse-report -t ${report} | head -1 | cut -d ' ' -f 3
}

get_id_key_hash()
{
	local report=${1}
	sev-guest-parse-report -i ${report} | sed -e '1d' -e '{N;s/[ \n]//g;}'
}

id_key_found()
{
	local id_key_hash=${1}
	ls ${KEYS_DIR} | grep ${id_key_hash} > /dev/null
}

lookup_id_key_data()
{
	local id_key_hash=${1}
	local data_file=${KEYS_DIR}/${id_key_hash}

	cat ${data_file}
}

is_cert_chain_valid()
{
	local work_dir=${1}
	${SEV_TOOL} --ofolder ${work_dir} --validate_cert_chain_vcek | \
		grep "Command Successful" > /dev/null
}

is_report_valid()
{
	local work_dir=${1}
	${SEV_TOOL} --ofolder ${work_dir} --validate_guest_report | \
		grep "Command Successful" > /dev/null
}

validate_report()
{
	local report=${1}

	if [ ! -r "${report}" ]; then
	       log "failed to read report file '${report}'."
	       return 1
	fi

	local id_key_hash=$(get_id_key_hash ${report})
	local tcb_version=$(get_tcb_version ${report})

	# Retrieve the certificates needed to validate the report
	${SEV_TOOL} --ofolder . --export_cert_chain_vcek ${tcb_version} > /dev/null

	# Check that the identity key hash matches the expected value and that the
	# guest report and it's cert chain validate correctly
	is_cert_chain_valid . && is_report_valid . && id_key_found ${id_key_hash}
}

main()
{
	# Change to a safe temporary directory
	local work_dir=$(mktemp -d /tmp/$(basename $0)-XXXXXX)
	pushd ${work_dir} > /dev/null

	# Extract the tarball provided in the POST operation
	tar -zxf /dev/stdin
	if [ "$?" -ne "0" ]; then
		cgi_response "Attestation Response" "Result" "Upload failed."
		exit 1
	fi

	log "Guest report received."

	local report=guest_report.bin
	local pubkey=wrap-key.pub

	# Validate the guest report and its certificate chain
	if ! validate_report ${report}; then
		log "Validation failed!"
		cgi_response "Attestation Response" "Result" "Validation failed."
		exit 2
	fi

	log "Guest report validated successfully!"

	# Retrieve the disk key for this guest
	local id_key_hash=$(get_id_key_hash ${report})
	local data=$(lookup_id_key_data ${id_key_hash})

	if [ -z "${data}" ]; then
		local msg="Disk key not found!"
		log "${msg}"
		cgi_response "Attestation Response" "Result" "${msg}"
		exit 3
	fi

	# Encrypt the disk key using the provided wrapping key
	local wrapped_key=$(echo -n ${data} | \
				openssl pkeyutl -pubin -inkey ${pubkey} -encrypt | \
				openssl enc -base64 -A)

	# Cleanup
	popd > /dev/null
	rm -rf ${work_dir}

	log "Sending (encrypted) disk key."

	# Send the required CGI response message
	cgi_response "Attestation Response" "Result" "key=${wrapped_key}"
	exit 0
}

main $@
