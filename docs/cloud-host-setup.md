### Cloud Host
#### Kernel, Hypervisor, and Guest UEFI Image

Currently, the simplest way to install a SEV-SNP environment with the proper kernel, qemu, and OVMF support is to use the AMDSEV repo.

1. Clone the [sev-snp-devel](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) branch of the AMDSEV repo:
    ```
    git clone --single-branch -b sev-snp-devel https://github.com/AMDESE/AMDSEV.git
    cd AMDSEV
    ```
2. Update the kernel branch name to the (experimental) sev-snp-part2-v6 branch:
    ```
    sed -i -e 's/sev-snp-part2-v5/sev-snp-part2-v6/' stable-commits
    ```
3. Run the build.sh script:
    ```
    ./build.sh
    ```
4. Install the resulting debian packages:
    ```
    sudo apt install *.deb
    ```

The Qemu and OVMF binaries are now installed in ./usr under the AMDSEV directory.

#### SEV-SNP Firmware

The SEV-SNP firmware version needed to run this example can be downloaded [here](../attestation/firmware). The firmware can be installed as follows:
```
mkdir -p /lib/firmware/amd/
cp sev.fw /lib/firmware/amd/sev.fw
```

#### sev-host tool (optional)

This tool is used to store the certificate chain (if any) needed to validate the VCEK signature on the SNP guest reports.

Building the sev-host tool requires the following development packages to be installed:
 - libssl-dev
 - uuid-dev

```
sudo apt install libssl-dev uuid-dev
```

The sev-host tool can then be built using make:
```
make
```

