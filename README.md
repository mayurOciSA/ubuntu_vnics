# Introduction

This project provides a Python script that generates a [netplan](https://netplan.readthedocs.io/en/stable/howto/) YAML configuration for an Oracle Cloud Infrastructure (OCI) *VM* compute instances running linux distribution of [Ubuntu 24+](https://ubuntu.com/). The script employs source routing(via policies) for network interfaces corresponding to secondary [VNICs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingVNICs.htm) of the Ubuntu instance. For all interfaces, the script will configure DNS Servers, Search domains within the netplan. This is particularly useful for users managing multiple network interfaces on Ubuntu OCI instances, as it simplifies the configuration process and reduces the potential for human error. 

# Setup

To set up the project, create a new directory named say *oci_ubuntu* with say full path of */path/to_dir/oci_ubuntu*. Then `cd` into directory */path/to_dir/oci_ubuntu* and place `ubuntu_netplan_oci.py`. 

Now follow these steps:

1. **Create a Python virtual environment**:
   `python3 -m venv venv`

2. **Activate the virtual environment**:
   - On macOS/Linux:
     `source ./venv/bin/activate`
   - On Windows:
     `.\venv\Scripts\activate`
3. **Install required packages**:
   Use the following command to install the necessary packages:
   `pip3 install  -r requirements.txt`,
   
## Usage

To use the script, from */path/to_dir/oci_ubuntu*, run the following command in your terminal:

```Shell
python3 ubuntu_netplan_oci.py --profile <OCI_CLI_PROFILE> [--instance-ocid <OCID>] [--dest-dir /path/to/dir] [--skip-primary]
```
If argument `--dest-dir` is passed you will get netplan config yaml in directory */path/to/dir* with file named `ubuntu-oci-netplan-config.yaml` . If not, then you will get the output on stdout. From instance OCID, the script will figure out the OCI region of the instance.

Example Usages:

From your dev box

```Shell
python3 ubuntu_netplan_oci.py --profile DEFAULT --instance-ocid ocid1.instance.oc1.iad.abcdefg123456 --dest-dir /path/to/dir
```

From OCI Compute instance running Ubuntu with Instance Principal setup, create the netplan for the same node

```Shell
python3 ubuntu_netplan_oci.py
```

## Input Parameters

- `--instance-ocid`: (Optional) The OCID of the instance. If not provided, the script will *attempt* to fetch it from the instance metadata service, assumption here being script is running on OCI Ubuntu node.
- `--profile`:(Optional) The OCI CLI profile name to use from the OCI config file (default: DEFAULT). Optional, if script is running on OCI instance with apt dynamic group and IAM policy is setup.
- `--dest-dir`:(Optional) The destination directory to write the netplan YAML configuration. If not provided, the output will be printed to stdout.
- `--skip-primary`:(Optional) If true, the primary VNIC will be skipped in the netplan config. DHCPv4 and DHCPv6 is supported by OCI for primary VNICs, hence user might choose to only configure the secondary VNICS. Default value: false.



## Using Instance Principal

Example definition of a dynamic group called say *dg_ubuntu* for nodes where you need the script to run

-`Any {instance.compartment.id = 'ocid1.compartment.oc1..exampleuniqueid2}`

IAM policy required for *dg_ubuntu*

-`Allow dynamic-group 'IAM Domain Name'/'dg_ubuntu' to read virtual-network-family in compartment <cmpt name>`

-`Allow dynamic-group 'IAM Domain Name'/'dg_ubuntu' to read instances in compartment <cmpt name>`


# Caution

1. In case you want to *completely* replace current Ubuntu netplan configuration with the configuration generated by the script, you would need to rename existing netplan YAML files under `/etc/netplan/*.yaml`. .You can do so as follows

   - `sudo find /etc/netplan -maxdepth 1 -name "*.yaml" -exec mv {} {}.bk \;`

2. Please note, incase you are using the script to only manage/configure secondary VNICs/interfaces on your Ubuntu instance, keep the netplan configuration file for your primary interface(usually named `/etc/netplan/<primary_interface_name>.yaml`) as it is. 

# Applying the New Configuration

Place script generated netplan `ubuntu-oci-netplan-config.yaml` under `/etc/netplan/`

Change file permissions with `chmod 600 /etc/netplan/ubuntu-oci-netplan-config.yaml`

Now you can apply it using the following commands:

1. **Test the new configuration**:
   sudo netplan --debug try

2. **Apply the new configuration**:
   sudo netplan --debug apply

> NOTE: Netplan processes all *.yaml files under `/etc/netplan/` in a lexicographical order. If the same interface say X is configured in multiple files, the file being processed later(lexicographically) with config for X, will override previous configs for X. 
Hence when `ubuntu-oci-netplan-config.yaml` has the configs for primary interface, it will override the configs of the default netplan config `enp0s6.yaml` for the same. 

# Verification

To verify that the new netplan configuration has been applied correctly, you can use the following commands:

1. **Ping Test**:
   `ping -I <source_ip> -c 4 www.google.com`

2. **Check Routing**:
   `ip route get www.google.com from <source_ip>`

3. **IPv6 Ping Test**:
   `ping6 -I <source_ip> -c 4 www.google.com`

4. **Check IPv6 Routing**:
   `ip -6 route get www.google.com from <source_ip>`

5. **Get Entire Effective Netplan Configurations**:
  `netplan get all`

1. **Check Netplan Status**:
   `netplan status --all`

2. **Check Route Tables**: 
   `ip route show table [all | table_id]`
   `ip -6 route show table [all | table_id]`

3. **Check DNS**
   `dig -b <source_ip> @169.254.169.254 www.google.com` ,
   `resolvectl status` , 
   `resolvectl query www.google.com --interface=eth1`

4. **Check netoworkd configs generated by netplan**
   `cat /run/systemd/network/*`

As applicable to your Ubuntu instance, test out primary IP and some of secondary IP addresses of both IPv4 and IPv6 types as `<source_ip>`, for all VNICs/interfaces, in the above commands. In addition you can also try within OCI destinations that your application on Ubunutu need to communicate.

By following these steps, you can ensure that your network configuration is correctly applied and functioning as expected.


# Future Improvements
1. Support for Ubuntu BM compute nodes on OCI, as it needs VLAN confgiured for each VNIC.
2. Adding support for cloud-init.
3. Adding support for auto and pre-configured scheduled sync to current OCI VCN/VNIC configuration for the Ubuntu compute node, similar to [`ocid` deamon](https://docs.oracle.com/en-us/iaas/oracle-linux/oci-utils/index.htm#ocid-daemon) on Oracle Linux.
4. Using kernel generated interface names within netplan configuration, when script runs on a Ubuntu compute on OCI.
5. Making script more strongly typed.

# Contact
Mayur Raleraskar - feedback_oci_virtual_networking_us_grp[at]oracle[dot]com

# Limitations and Disclaimer 
**The script is offerred without any promised support.** 
**The script is offerred without any liability in any way.** 

This script is intended to get you started with a *reference* netplan configuration for Ubuntu on OCI. It is a work in progress.

You might need to see what further changes your applications(running on your Ubuntu OCI compute nodes) might need. 

You need to seperately manage firewall, NSG and security lists settings. 

The netplan configuration generated by the script renames the interfaces. This can cause trouble to some applications running on the node, like say a firewall, by disrupting their in-use connections. If you face this issue, either modify the generated netplan config with the same names for the network interfaces, as you have currently have on the node or apply the config before the start of any application on the node, for example during node startup.

If your Ubuntu VM has different VNICs with subnets having overlapping CIDRs, please make sure you place such interfaces(these VNICs) in different network namespaces within Ubuntu OS and consequently, split netplan configuration *manually* for each different network namespaces. 

The script turns off DHCPv4, DHCPv6 and Router Advertisement for IPv6 for all interfaces/VNICs. For each update to VNICs of the node or its IP addresses, you would need to regenerate the netplan and apply it again.

# Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

For updating the `THIRD_PARTY_LICENCES.txt`, use the following command

`pip-licenses --format=plain-vertical --with-license-file --no-license-path --with-authors > THIRD_PARTY_LICENCES.txt`