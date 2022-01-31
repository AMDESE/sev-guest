#!/bin/bash
#
#

set -e
trap cleanup ERR EXIT

DEFAULT_IMG_NAME="encrypted.qcow2"
DEFAULT_IMG_SIZE="20G"

LINUX_RESERVED_PART_CODE="8300"

BOOT_PART_NR="1"
BOOT_PART_NAME="boot"
BOOT_PART_LABEL="${BOOT_PART_NAME}"

EFI_PART_NR="2"
EFI_PART_NAME="UEFI"
EFI_PART_LABEL="${EFI_PART_NAME}"

LUKS_PART_NR="3"
LUKS_PART_NAME="luks-rootfs"
LUKS_PART_LABEL="${LUKS_PART_NAME}"
LUKS_DM_NAME="${LUKS_PART_NAME}"

LUKS_NBD="/dev/nbd0"
LUKS_MNT=$(mktemp -d /tmp/luks-mnt-XXXXXX)

REF_NBD="/dev/nbd1"
REF_MNT=$(mktemp -d /tmp/ref-mnt-XXXXXX)

highlight()
{
	echo -e "\e[1;33m${@}\e[0m"
}

cleanup()
{
	echo
	highlight "Cleaning up..."

	# Unmount filesystems
	[ -d ${REF_MNT} ] && umount -R ${REF_MNT} && rmdir ${REF_MNT}
	[ -d ${LUKS_MNT} ] && umount -R ${LUKS_MNT} && rmdir ${LUKS_MNT}

	# Close the LUKS device
	[ -f /dev/mapper/${LUKS_DM_NAME} ] && cryptsetup close ${LUKS_DM_NAME}

	# Disconnect the nbd devices
	qemu-nbd -d ${LUKS_NBD}
	qemu-nbd -d ${REF_NBD}
}

stderr()
{
	echo "${@}" > /dev/stderr
}

die()
{
	stderr "ERROR: ${FUNCNAME[1]}: ${@}"
	exit 1
}

print_usage()
{
	stderr
	stderr "Usage: $(basename ${0}) ref-image [image-name] [image-size]"
	stderr
	stderr "Create a LUKS-encrypted QCOW2 image from an unencrypted reference QCOW2 image."
	stderr
	stderr "If image-name and/or image-size are not specified, the output file"
	stderr "name will be ${DEFAULT_IMG_NAME} and the size will be ${DEFAULT_IMG_SIZE}."
	stderr
}

create_disk_partitions()
{
	local dev=${1}

	[ -z "${dev}" ] && die "disk device unspecified"

	sgdisk --zap-all ${dev}

	sgdisk --new=${BOOT_PART_NR}:0:+100M ${dev}	# /boot
	sgdisk --typecode=${BOOT_PART_NR}:8301 ${dev}	# type = Linux reserved
	sgdisk --change-name=${BOOT_PART_NAME}:${BOOT_PART_NAME} ${dev}

	sgdisk --new=${EFI_PART_NR}:0:+100M ${dev}		# /boot/efi
	sgdisk --typecode=${EFI_PART_NR}:ef00 ${dev}	# type = EFI System Partition
	sgdisk --change-name=${EFI_PART_NR}:${EFI_PART_NAME} ${dev}

	sgdisk --new=${LUKS_PART_NR}:0:0 ${dev}		# /
	sgdisk --typecode=${LUKS_PART_NR}:8309 ${dev}	# type = Linux LUKS
	sgdisk --change-name=${LUKS_PART_NR}:${LUKS_PART_NAME} ${dev}

	sgdisk --print ${nbd}
}

get_partition_number()
{
	local dev=${1}
	local code=${2^^}	# Convert to upper case

	[ -z "${dev}" ] && die "block device is unspecified."
	[ -z "${code}" ] && die "partition code is unspecified."

	sgdisk --print ${dev} | \
		grep "^ \+[0-9]\+" | \
		sed -e 's/  */ /g' | \
		cut -d ' ' -f 2,7 | \
		grep ${code} | \
		cut -d ' ' -f 1
}

add_fstab_entry()
{
	local fstab=${1}
	local entry=${2}

	[ -z "${fstab}" ] && die "fstab location is empty!"
	[ -z "${entry}" ] && die "fstab entry is empty!"

	[ ! -w "${fstab}" ] && die "${fstab} is not writable!"

	# Read the existing fstab entries
	local -a fstab_entries=( "${entry}" )
	readarray -O 1 -t fstab_entries < ${fstab}

	# Sort all fstab entries by mount point and write the new fstab
	for i in ${!fstab_entries[@]}; do
		echo ${fstab_entries[${i}]}
	done | sort -k 2,3 -o ${fstab}
}

run_chroot_cmd()
{
	local new_root=${1}
	shift

	[ -z "${new_root}" ] && die "new root directory is empty!"
	[ ${#} -eq 0 ] && die "no command specified!"

	# Mount /dev and virtual filesystems inside the chroot
	mount --bind /dev ${new_root}/dev
	mount --bind /dev/pts ${new_root}/dev/pts
	mount -t proc proc ${new_root}/proc
	mount -t sysfs sysfs ${new_root}/sys
	mount -t tmpfs tmpfs ${new_root}/run

	chroot "${new_root}" \
		/usr/bin/env -i HOME=/root TERM="${TERM}" PATH=/usr/bin:/usr/sbin \
		${@}

	# Unmount virtual filesystems
	umount ${new_root}/dev{/pts,}
	umount ${new_root}/{sys,proc,run}
}

main()
{
	local ref_img=${1}
	local new_img=${2:-${DEFAULT_IMG_NAME}}
	local size=${3:-${DEFAULT_IMG_SIZE}}

	# Check arguments
	if [ "${#@}" -gt 3 -o -z "${ref_img}" ]; then
		print_usage
		exit 1
	fi

	# If we are not root, re-run with root privileges.
	if [ "${UID}" -ne 0 ]; then
		highlight "root priviliges are required. Re-running under sudo..."
		exec sudo ${0} ${@}
	fi

	[ ! -r "${ref_img}" ] && die "${ref_img} is not readable!"

	# Create the base qcow2 image
	qemu-img create -f qcow2 ${new_img} ${size}

	# Connect the image files to nbd devices
	local new_img_nbd=${LUKS_NBD}
	local ref_img_nbd=${REF_NBD}

	[ ! -r "${new_img_nbd}" -o ! -r ${ref_img_nbd} ] && modprobe nbd

	qemu-nbd -c ${new_img_nbd} -f qcow2 ${new_img}
	qemu-nbd -c ${ref_img_nbd} -f qcow2 ${ref_img}

	# Partition the virtual disk
	echo
	highlight "Partitioning virtual disk..."
	create_disk_partitions ${new_img_nbd}

	local boot_partition=${new_img_nbd}p${BOOT_PART_NR}
	local efi_partition=${new_img_nbd}p${EFI_PART_NR}
	local luks_partition=${new_img_nbd}p${LUKS_PART_NR}

	# Setup LUKS on the root partition
	echo
	highlight "Setting up LUKS encryption for the root partition..."
	cryptsetup luksFormat ${luks_partition}

	echo
	highlight "Unlocking the LUKS partition for installation..."
	cryptsetup open ${luks_partition} ${LUKS_DM_NAME}

	# Format filesystems
	echo
	highlight "Formatting ${BOOT_PART_NAME} partition..."
	mkfs.ext4 -L ${BOOT_PART_LABEL} ${boot_partition}

	echo
	highlight "Formatting ${EFI_PART_NAME} partition..."
	mkfs.vfat -F 16 -n ${EFI_PART_LABEL} ${efi_partition}

	# Determine which partition on the reference image contains the rootfs
	local ref_linux_part=$(get_partition_number ${ref_img_nbd} ${LINUX_RESERVED_PART_CODE})
	local ref_rootfs=${ref_img_nbd}p${ref_linux_part}

	echo
	highlight "Copying files from reference image to LUKS image..."
	dd if=${ref_rootfs} of=/dev/mapper/${LUKS_DM_NAME} status=progress

	# Mount the image files
	local ref_mnt=${REF_MNT}
	local luks_mnt=${LUKS_MNT}

	mkdir -p ${ref_mnt}
	mount ${ref_rootfs} ${ref_mnt}

	mkdir -p ${luks_mnt}
	mount /dev/mapper/${LUKS_DM_NAME} ${luks_mnt}

	# Move the contents of /boot to the new boot partition
	mv ${luks_mnt}/boot ${luks_mnt}/boot.orig
	mkdir -p ${luks_mnt}/boot
	mount ${boot_partition} ${luks_mnt}/boot
	mv ${luks_mnt}/boot.orig/* ${luks_mnt}/boot
	rm -rf ${luks_mnt}/boot.orig

	# Update etc/fstab to include the new boot partition
	echo
	highlight "Updating etc/fstab..."
	add_fstab_entry ${luks_mnt}/etc/fstab "LABEL=boot /boot ext4 defaults 0 1"

	# Add a crypttab entry for the LUKS partition
	echo
	highlight "Updating etc/crypttab..."

	. ${luks_mnt}/etc/os-release

	if [ "${ID}" == "ubuntu" -a -w ${luks_mnt}/etc/crypttab ]; then
		local uuid=$(blkid -s UUID -o value ${luks_partition})
		echo "${LUKS_DM_NAME} UUID=${uuid} none luks" >> ${luks_mnt}/etc/crypttab
		run_chroot_cmd ${luks_mnt} update-initramfs -u -k all
	fi

	# Install GRUB
	echo
	highlight "Installing GRUB..."
	mount ${efi_partition} ${luks_mnt}/boot/efi
	run_chroot_cmd ${luks_mnt} grub-install --target=x86_64-efi ${new_img_nbd}

	# Update the GRUB menu
	#
	# Disabling os-prober ensures that only the kernels in /boot are added
	# to the menu, and OSes on other disks (like the host OS) are ignored.
	cp ${luks_mnt}/etc/default/grub ${luks_mnt}/etc/default/grub.orig
	echo "GRUB_DISABLE_OS_PROBER=true" >> ${luks_mnt}/etc/default/grub
	run_chroot_cmd ${luks_mnt} update-grub
	mv ${luks_mnt}/etc/default/grub.orig ${luks_mnt}/etc/default/grub

	echo
	highlight "Successfully created ${new_img}!"
	exit 0
}

main $@
