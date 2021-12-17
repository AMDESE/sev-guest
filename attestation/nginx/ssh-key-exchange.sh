#!/usr/bin/bash
#
# ssh-key-exchange.sh
#
# Validate a SEV-SNP guest report and install the associated public SSH key.

SEV_TOOL=/home/bc/src/git/sev-tool/src/sevtool
LOGFILE=/var/www/cgi.log

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

validate_pubkey()
{
	local dir=$1
	local report_hash=$(sev-guest parse-report -d ${dir}/guest_report.bin | cut -d ' ' -f3)
	local pubkey_hash=$(sha512sum ${dir}/pubkeys | cut -d ' ' -f1)

	# Rename the .cert files to .pem
	for cert in *.cert; do
		mv ${cert} ${cert%.cert}.pem
	done

	# Check that the report hash matches the pubkey and that the
	# guest report and it's cert chain validate correctly
	[ "${report_hash}" == "${pubkey_hash}" ] && \
	${SEV_TOOL} --ofolder ${dir} --validate_cert_chain_vcek && \
	${SEV_TOOL} --ofolder ${dir} --validate_guest_report
}

update_known_hosts()
{
	local dir=$1
	local hostname=$(cat ${dir}/hostname)
	local address=$(cat ${dir}/address)
	local inotify_dir="/var/www/attestation"

	if [ -d ${inotify_dir} ]; then
		ssh-keyscan -H -t rsa ${address} > ${inotify_dir}/${hostname} 2>&1
	fi
}

main()
{
	# Change to a safe temporary directory
	local work_dir=$(mktemp -d /tmp/$(basename $0)-XXXXXX)
	pushd ${work_dir} > /dev/null

	# Extract the tarball provided in the POST operation
	tar -xf /dev/stdin
	if [ "$?" -ne "0" ]; then
		cgi_response "Attestation Response" "Result" "Upload failed."
		exit 1
	fi

	log "Guest report received."

	# Validate the guest report and its certificate chain
	if validate_pubkey ${work_dir}; then
		log "Guest report validated successfully!"
		update_known_hosts ${work_dir}
		log "known_hosts entry generated."
	else
		log "Validation failed!"
		cgi_response "Attestation Response" "Result" "Validation failed."
		exit 2
	fi

	# Cleanup
	popd > /dev/null
	rm -rf ${work_dir}

	# Send the required CGI response message
	cgi_response "Attestation Response" "Result" "SUCCESS"
	exit 0
}

main $@
