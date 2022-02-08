# Guest Owner Infrastructure Setup

This guide will cover the installation and configuration of the services required from the Guest Owner's infrastructure. All services can run on the same server, referred to as the "attestation server."

The necessary services include the following:
* [SEV Tool](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#sev-tool)
* [`sev-guest` Utility](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#sev-guest-utility)
* [Web Server](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#web-server)
* [CGI Backend](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#cgi-backend)
* [Disk Key Database](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#disk-key-database) (*disk encryption example only*)
* [Guest Disk Encryption](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#guest-disk-encryption) (*disk encryption example only*)
* [User Notification](https://github.com/AMDESE/sev-guest/blob/main/docs/guest-owner-setup.md#user-notification) (*SSH key exchange example only*)

**All commands shown below must be executed from the top-level directory of this repository.**

## SEV Tool

The sev-tool is useful to retrieve the VCEK for a platform and to verify the signatures in the attestation report. 

The build dependencies can be installed as follows:
```
sudo apt install git make gcc zip wget uuid-dev libvirt-dev automake autoconf libssl-dev g++
```

Issue the following commands to clone, build, and install the sev-tool:
```
pushd ..
git clone https://github.com/AMDESE/sev-tool
cd sev-tool
autoreconf -vif
./configure
make -j $(getconf _NPROCESSORS_ONLN)
sudo make install
popd
```

## `sev-guest` Utility

This tool is used for all tasks necessary to handle SNP guest reports. It can:
 - retrieve a SNP guest report from the SEV-SNP firmware,
 - parse and print the SNP guest report fields,
 - and retrieve the certificate chain (if any) needed to validate the VCEK signature on the SNP guest reports.

Building the sev-guest tool requires the `linux-libc-dev` package from the SEV-SNP host kernel build:
```
sudo apt install /path/to/linux-libc-dev
```

**NOTE:** For instructions to build SEV-SNP kernels, see the [sev-snp-devel](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) branch of the `AMDSEV` repository.

The `sev-guest` utility also requires the following development packages to be installed:
```
sudo apt install uuid-dev
```

Lastly, [OpenSSL](https://github.com/openssl/openssl.git) >= 3.0.0 must also be available on the system:

```
pushd ..
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure
make -j $(getconf _NPROCESSORS_ONLN)
sudo make install
sudo ldconfig /usr/local/lib64
popd
```

The `sev-guest` utility can then be built using make:
```
make -j $(getconf _NPROCESSORS_ONLN)
```

## Web Server

The web server used in these examples is Nginx, and CGI services are provided by FastCGI wrapper.

On Ubuntu, these packages can be installed using apt:
```
sudo apt install nginx fcgiwrap
```

An Nginx configuration file is provided in [../attestation/nginx/http.conf](../attestation/nginx/http.conf). This file configures a simple HTTP server with FastCGI enabled. The domain name is attestation.example.com by default, but feel free to customize this to your liking.

Edit the provided Nginx example configuration to include the IP address of your machine, or simply execute the commands below:
```
IP=$(ip -brief -family inet address show scope global | grep -w UP | grep -o -m1 "[0-9]*\.[0-9*\.[0-9]*\.[0-9]*")
sed -i "s/LISTEN_ADDRESS/${IP}/" attestation/nginx/http.conf
```

Copy the configuration file to the Nginx configuration directory and restart Nginx using the following commands:
```
sudo cp attestation/nginx/http.conf /etc/nginx/conf.d
sudo nginx -s reload
```

Finally, add a DNS entry in /etc/hosts to resolve the IP address of the example web server:
```
echo | sudo tee -a /etc/hosts
echo "# SEV-SNP example attestation server" | sudo tee -a /etc/hosts
IP=$(ip -brief -family inet address show scope global | grep -w UP | grep -o -m1 "[0-9]*\.[0-9*\.[0-9]*\.[0-9]*")
echo "${IP} attestation.example.com" | sudo tee -a /etc/hosts
```

*nginx test here*

## CGI Backend

The CGI backend consists of the following components:
* CGI Scripts
* Disk Key Database

### CGI Scripts

Create the cgi-bin directory and populate it with the example scripts:
```
sudo mkdir -p /usr/lib/cgi-bin
sudo cp attestation/nginx/*.sh /usr/lib/cgi-bin
sudo chown www-data:www-data /usr/lib/cgi-bin/*.sh
```

The CGI scripts can now be called from remote clients by sending an HTTP POST command to the URL of the example attestation server with '/cgi-bin/[script name]' appended.

As a test, sending an empty POST command to the `ssh-key-exchange.sh` script should result in a HTML response indicating that the upload failed:
```
$ curl --data-binary @/dev/null -H "Content-Type: application/octet-stream" http://attestation.example.com/cgi-bin/ssh-key-exchange.sh
<HTML>
<HEAD><TITLE>Attestation Response</TITLE></HEAD>
<BODY>
<H1>Result</H1><HR>
Upload failed.
</BODY></HTML>
```

If the `curl` command above results in an HTML response from the attestation server, then the CGI backend is setup correctly.

**NOTE:** The script failure is expected, because the `ssh-key-exchange.sh` script expects the POST command to contain a tarball with an attestation report and other supporting information. (See [guest-owner-user-data.yaml](attestation/cloud-init/guest-owner-user-data.yaml) to see how to construct the input tarball.)

### Disk Key Database

The `disk-key.sh` CGI script requires the directory `/var/www/keys` to exist and contain files named after the hash of the identity key for each guest. The content of the files must be the plaintext disk encryption passphrase without any trailing '\n' character. To protect the secrecy of the keys, the directory `/var/www/keys` should be readable only by the `www-data` user.

An identity key can be generated for a guest using OpenSSL:
```
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:"P-384" -out id-key.pem
openssl pkey -in id-key.pem -pubout -out id-key.pub
```

There is a helper script in the `scripts/` directory that can properly create the files in `/var/www/keys` given the file name of the identity key in PEM format:
```
./scripts/create-key-db-entry.sh id-key.pem
```

The `create-key-db-entry.sh` script will prompt for the passphrase (with echo disabled) to prevent the passphrase from being logged in the shell history file.

Although the files in `/var/www/keys/` hold passphrases in plaintext, the `disk-key.sh` CGI script will encrypt the passphrase before including it in the CGI response.

## Guest Disk Encryption

The `create-luks-qemu-img.sh` script in the `scripts/` directory can be used to prepare a LUKS-encrypted virtual machine image using an existing QCOW2 image as a base. Additionally, debian packages may be listed on the command line to be installed into the encrypted image. This allows for the installation of the SEV-SNP kernel packages as well as the `sev-guest` tool in this repository in a single provisioning step.

First, use the debian control files in the `debian/` directory to create installable debian packages for the OpenSSL binaries, headers, and documentation:
```
pushd ../openssl
for control in ../sev-guest/debian/control.openssl3-*; do equivs-build ${control}; done
popd
```

Build an installable package for the `sev-guest` tool as well:
```
make guest-deb
```

The `create-luks-qemu-img.sh` script requires a base virtual machine image to install into the encrypted filesystem. For the examples in this repository, it is recommended to use an Ubuntu cloud image as the base.

Download the latest 20.04 LTS server cloud image to use as a base:
```
wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64-disk-kvm.img
```

Invoke the `create-luks-qemu-img.sh` script to create a new QCOW2 image file called `encrypted.qcow2`, resize it to 20GB, setup LUKS encryption for the root filesystem, and install all of the packages necessary for the Disk Encryption example. This command assumes that the SEV-SNP guest kernel packages are located in `../AMDSEV/linux/guest/` and the OpenSSL packages are located in `../openssl/`.
```
create-luks-qemu-img.sh encrypted.qcow2 20G ../AMDSEV/linux/guest/*.deb ../openssl/openssl3_*.deb sev-guest*.deb
```

## User Notification

The `ssh-key-exchange.sh` CGI script requires that the directory `/var/www/attestation/` exists and is readable by all users on the system. This script will craft `known_hosts` entries for SEV-SNP guests that successfully attest and will place them into `/var/www/attestation/`. Users on the system that wish to import the SSH public key of trusted SEV-SNP guests can subscribe to notifications about changes to the `/var/www/attestation/` directory using `inoticoming`.

These commands will create the `/var/www/attestation/` directory with the appropriate permissions:
```
sudo mkdir -p /var/www/attestation
sudo chown www-data:www-data /var/www/attestation
sudo chmod o+r /var/www/attestation
```

Other users on the attestation server can use the [update-known-hosts.sh](../attestation/inoticoming/update-known-hosts.sh) script along with `inoticoming` to automatically update their `~/.ssh/known_hosts` file with the fingerprint of SEV-SNP guest SSH public keys by executing the following commands:
```
mkdir -p ~/bin
wget -O ~/bin/update-known-hosts.sh https://github.com/AMDESE/sev-guest/raw/main/attestation/inoticoming/update-known-hosts.sh
chmod a+x ~/bin/update-known-hosts.sh
inoticoming /var/www/attestation ~/bin/update-known-hosts.sh /var/www/attestation/\{\} \;
```

`inoticoming` will log each invocation of the `update-known-hosts.sh` script using the system logger. To view the logs, execute the following command:
```
journalctl _COMM=inoticoming
```
