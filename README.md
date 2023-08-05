# SEV-SNP Attestation Examples

This repository contains source, scripts, and configuration files for several open source tools that can be used together to demonstrate one way to perform remote attestation of SEV-SNP guests.

Note that these materials are intended for educational use only and come with no guarantee of fitness for any purpose.

## Architectural Overviews

Architectural discussions and security considerations for each example are available in the [docs](docs) directory. Currently, this repository contains the following examples:

* [SSH Key Exchange](docs/ssh-key-exchange.md): Using remote attestation to securely exchange SSH public keys.
* Encrypted Disk Unlock: Using remote attestation to retrieve a disk encryption key and unlock an encrypted root filesystem.

## Example Setup

Installation instructions for the cloud host and the Guest Owner infrastructure are outlined below. Note that for simplicity, these two servers can be the same physical machine.

 * [Cloud Host Setup](docs/cloud-host-setup.md)
 * [Guest Owner Setup](docs/guest-owner-setup.md)

## Future Work

Future updates to this repository will include additional examples of how to perform the following tasks:

 - [x] Construct the ID Block for the SNP guest. (Done. Documentation pending. See `sev-host-identity --help` for more information.)
 - [ ] Verify the ID Block in the attestation report. (in progress)
 - [x] Shift the attestation flow to the initrd and receive a disk encryption key. (Done. Documentation pending. See [attestation/cryptsetup-initramfs](attestation/cryptsetup-initramfs))

---

## Resources

1. [AMD SEV-SNP ABI Specification (PDF)](https://www.amd.com/system/files/TechDocs/56860.pdf)
2. [AMD Signing Key (ASK) and AMD Root Key (ARK) Certificates for Milan Processors](https://download.amd.com/developer/eula/sev/ask_ark_milan.cert)

