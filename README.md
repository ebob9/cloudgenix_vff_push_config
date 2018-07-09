cloudgenix_vff_push_config
----------------
#### Synopsis
Helper script to PUSH a Virtual Form Factor (VFF) config to a newly booted virtual ION waiting for config.

Available methods:
 * Serial (requires knowledge of tty/pty path of serial port)
   * Serial also requires PySerial module, which may need an additional install.
 * Telnet (KVM serial redirect to TCP port/telnet style)
 * virsh console (KVM/QEMU without serial)
 * SSH (for AWS/GCE/Azure - Can use password or private key.)

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * pyserial >= 3.0 - <https://pythonhosted.org/pyserial/>
    * pexpect >= 4.0 - <https://pexpect.readthedocs.io/en/stable/>

#### Installation
Available via PIP - `pip install cloudgenix_vff_push_config`. 
PIP should add a `vff_push_config` or `vff_push_config.exe` command to the path.

#### Examples
Example configuration files for CloudGenix Virtual Form Factors (VFF) are in ./example_configs subdirectory.
For more info on the CloudGenix VFF config file options, see <https://support.cloudgenix.com>


Serial example usage:
```
aaron@partner-lab-traf:~/vff_push_config$ sudo vff_push_config serial --file ./example_configs/example.cfg --pty /dev/pts/2
[VFF_PUSH] Starting VFF Config Push script.
[VFF_PUSH] Current directory is /home/aaron/vff_push_config
[VFF_PUSH]   Successfully loaded 373 chars from ./example_configs/example.cfg.
[VFF_PUSH_SERIAL] Opening /dev/pts/2
[VFF_PUSH_SERIAL] 1 Got config prompt. Continuing.
[VFF_PUSH_SERIAL] Setting up config push.
[VFF_PUSH_SERIAL] Config successfully sent! Exiting.
aaron@partner-lab-traf:~/vff_push_config$
```

Telnet example usage:
```
aaron@partner-lab-traf:~/vff_push_config$ vff_push_config telnet --file ./example_configs/example.cfg --host 127.0.0.1 --port 4000
[VFF_PUSH] Starting VFF Config Push script.
[VFF_PUSH] Current directory is /home/aaron/vff_push_config
[VFF_PUSH]   Successfully loaded 373 chars from ./example_configs/example.cfg.
[VFF_PUSH_TELNET] Opening 127.0.0.1:4000
[VFF_PUSH_TELNET] 127.0.0.1:4000 Opened
[VFF_PUSH_TELNET] 1 Got config prompt. Continuing.
[VFF_PUSH_TELNET] Setting up config push.
[VFF_PUSH_TELNET] Config successfully sent! Exiting.
aaron@partner-lab-traf:~/vff_push_config$
```

Virsh console example usage:
```
aaron@partner-lab-traf:~/vff_push_config$ vff_push_config virsh --domain  Test_script_kvm4_ion_1 --file example_configs/example.yaml
[VFF_PUSH] Starting VFF Config Push script.
[VFF_PUSH] Current directory is /home/aaron/vff_push_config
[VFF_PUSH]   Successfully loaded 380 chars from example_configs/example.yaml.
[VFF_PUSH_VIRSH] Launched '/usr/bin/virsh console Test_script_kvm4_ion_1', waiting for prompt.
[VFF_PUSH_VIRSH] 1 Got config prompt. Continuing.
[VFF_PUSH_VIRSH] Setting up config push.
[VFF_PUSH_VIRSH] Config successfully sent! Exiting.
aaron@partner-lab-traf:~/vff_push_config$
```

SSH console example usage:
```
aaron@partner-lab-traf:~/vff_push_config$ vff_push_config ssh --file example_configs/example.yaml --host 172.22.5.244 --user virtualsetup --privkey ../TME-LAB-CONTROLLER.pem
[VFF_PUSH] Starting VFF Config Push script.
[VFF_PUSH] Current directory is /home/aaron/vff_push_config
[VFF_PUSH]   Successfully loaded 380 chars from example_configs/example.yaml.
[VFF_PUSH_SSH] Connecting to virtualsetup@172.22.5.244:22, Password: No, Private Key: Yes. Waiting for prompt.
[VFF_PUSH_SSH] 1 Got config prompt. Continuing.
[VFF_PUSH_SSH] Setting up config push.
[VFF_PUSH_SSH] Config successfully sent! Exiting.
aaron@partner-lab-traf:~/vff_push_config$
```

KVM/QEMU specific notes:
 * To set up serial port pty - add `--serial=pty` to virt-install command.
   * To determine pty filename, do `virsh dumpxml "VMNAME" | grep console | grep pty`. Example Output: `<console type='pty' tty='/dev/pts/2'>`
 * To set up serial port telnet listener - add `--serial tcp,host=<IF IP or 0.0.0.0>:<TCP PORT>,mode=bind,protocol=telnet` to virt-install command.

#### License
MIT

#### Version
Version | Changes
------- | --------
**1.1.1**| Fix parser_type and global config file data
**1.1.0**| Updated with Dynamic menu item support, and minor fixes.
**1.0.0**| Initial Release.