# Cloud Host
## Kernel, Hypervisor, and Guest UEFI Image

Currently, the simplest way to install a SEV-SNP environment with the proper kernel, qemu, and OVMF support is to use the AMDSEV repo.

1. Clone the [sev-snp-devel](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) branch of the `AMDSEV` repo:
```
git clone --single-branch -b sev-snp-devel https://github.com/AMDESE/AMDSEV.git
cd AMDSEV
```
2. Run the build.sh script:
```
./build.sh
```
3. Install the resulting debian packages:
```
sudo apt install linux/host/*.deb
```

The Qemu and OVMF binaries are now installed in `./usr` under the `AMDSEV` directory.

## SEV-SNP Firmware

The SEV-SNP firmware version needed to run this example can be downloaded [here](../attestation/firmware). The firmware can be installed as follows:
```
mkdir -p /lib/firmware/amd/
cp attestation/firmware/sev.fw /lib/firmware/amd/sev.fw
```

## `sev-host` Tool (Optional)

This tool is used to store the certificate chain (if any) needed to validate the VCEK signature on the SNP guest reports.

Building the `sev-host` tool requires the `linux-libc-dev` package from the SEV-SNP host kernel build:
```
sudo apt install ../AMDSEV/linux/host/linux-libc-dev*.deb
```

The `sev-host` utility also requires the following development packages to be installed:
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

The `sev-host` utility can then be built using make:
```
make -j $(getconf _NPROCESSORS_ONLN)
```
