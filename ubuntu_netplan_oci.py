#!/usr/bin/env python3
"""
This script uses the OCI Python SDK to generate a netplan YAML configuration for an OCI compute instance running Ubuntu 24+ OS.

It supports:
  - Using an instance OCID passed via command-line or, if not provided and if code is running on OCI instance itself, fetching it via the instance metadata service.
  - Using OCI CLI config (from file) if available; otherwise, it falls back to Instance Principals if running on OCI instance itself.
  - No need to provide region, code extracts the full region from the instance OCID.
  - Retrieving the instance's compartment (assuming instance and its all VNICs share the same compartment).
  - Collecting detailed VNIC information (including IP addresses, DNS from DHCP options, and subnet gateways).
  - Generating a netplan configuration with policy-based routing for all secondary VNICs.
  
Usage:
    ./ubuntu_netplan_oci.py --profile <OCI_CLI_PROFILE> [--instance-ocid <OCID>] [--dest-dir /path/to/dir]
"""

import argparse
import os
import sys
import traceback
import ipaddress
import logging
import requests
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

import oci
from oci import regions

# Constants for default DNS values.
DEFAULT_IPV4_DNS = "169.254.169.254"
DEFAULT_IPV6_DNS = "fd00:00c1::a9fe:a9fe"
INSTANCE_METADATA_URL = "http://169.254.169.254/opc/v1/instance/"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_instance_ocid(provided_ocid=None):
    """
    Returns the instance OCID either from the provided argument or via the instance metadata service.
    """
    if provided_ocid:
        logger.info("Using instance OCID from argument.")
        return provided_ocid
    try:
        logger.info("Attempting to get instance OCID from metadata service.")
        response = requests.get(INSTANCE_METADATA_URL, timeout=5)
        response.raise_for_status()
        metadata = response.json()
        ocid = metadata.get("id")
        if not ocid:
            raise ValueError("Instance metadata does not contain 'id'")
        logger.info("Fetched instance OCID from metadata service.")
        return ocid
    except Exception as e:
        logger.error("Failed to obtain instance OCID from metadata: %s", str(e))
        raise

def load_oci_config(profile):
    """
    Loads OCI configuration from file if exists; otherwise returns an empty dict to trigger Instance Principals.
    """
    config_path = os.path.expanduser("~/.oci/config")
    if os.path.exists(config_path):
        try:
            config = oci.config.from_file(config_path, profile_name=profile)
            logger.info("Loaded OCI config from file using profile '%s'.", profile)
            return config
        except Exception as e:
            logger.error("Error loading OCI config file: %s", str(e))
            raise
    else:
        logger.info("OCI CLI config file not found; falling back to Instance Principals.")
        return {}

def extract_region_from_ocid(ocid):
    """
    Extracts the region part from the instance OCID.
    Format: ocid1.instance.oc1.<region_or_short_code>.<...>
    If the region part is a three-letter code (e.g. "iad"), use the OCI SDK mapping to get the full region name.
    """
    try:
        parts = ocid.split('.')
        region_part = parts[3]
        if '-' not in region_part:
            region = regions.REGIONS_SHORT_NAMES[region_part]
        else:
            region = region_part
        logger.info("Extracted region '%s' from Instance OCID.", region)
        return region
    except Exception as e:
        logger.error("Failed to extract region from Instance OCID: %s", str(e))
        raise

def get_virtual_network_client(config, region):
    """
    Returns a VirtualNetworkClient instance. Uses Instance Principals if config is empty.
    """
    if config:
        return oci.core.VirtualNetworkClient(config)
    else:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        vnClient = oci.core.VirtualNetworkClient(config={}, signer=signer)
        vnClient.base_client.set_region(region) 
        return vnClient


def get_compute_client(config, region):
    """
    Returns a ComputeClient instance. Uses Instance Principals if config is empty.
    """
    if config:
        return oci.core.ComputeClient(config)
    else:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        computeClient = oci.core.ComputeClient(config={}, signer=signer)
        computeClient.base_client.set_region(region) 
        return computeClient

from types import SimpleNamespace
def dict_to_namespace(dictionary):
    if isinstance(dictionary, dict):
        return SimpleNamespace(**{key: dict_to_namespace(value) for key, value in dictionary.items()})
    elif isinstance(dictionary, list):
        return [dict_to_namespace(item) if isinstance(item, dict) else item for item in dictionary]
    else:
        return dictionary
    
def get_dhcp_options(vn_client, dhcp_options_id):
    """
    Get raw JSON response for DHCP options using the base_client.call_api method.
    We are using raw API calls as the SDK does not have a upto date model for DHCPOptions, with all the fields.
    """
    resource_path = "/dhcps/{dhcpId}"
    method = "GET"
    path_params = {"dhcpId": dhcp_options_id}
    header_params = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = vn_client.base_client.call_api(
        resource_path=resource_path,
        method=method,
        path_params=path_params,
        header_params=header_params,
        response_type="object"  

    )
    # response.data is a dictionary, convert it to a namespace object
    dhcp_opts_obj = dict_to_namespace(response.data)
    return dhcp_opts_obj  

def find_ipv6_prefix(ipv6_addr, subnet):
    """
    For a given IPv6 address and subnet details, determine the prefix length.
    The subnet may have one or multiple IPv6 CIDR blocks.
    """
    if hasattr(subnet, 'ipv6_cidr_block') and subnet.ipv6_cidr_block:
        network = ipaddress.IPv6Network(subnet.ipv6_cidr_block, strict=False)
        if ipaddress.IPv6Address(ipv6_addr) in network:
            return network.prefixlen
    if hasattr(subnet, 'ipv6_cidr_blocks') and subnet.ipv6_cidr_blocks:
        for cidr in subnet.ipv6_cidr_blocks:
            network = ipaddress.IPv6Network(cidr, strict=False)
            if ipaddress.IPv6Address(ipv6_addr) in network:
                return network.prefixlen
    logger.warning("Could not determine prefix length for IPv6 address %s; using /64 as default", ipv6_addr)
    return 64


    
def get_dns_info(dhcp_opts, subnet, vcn):
    subnet_search_domain = subnet.subnet_domain_name
    vcn_search_domain = vcn.vcn_domain_name
    if subnet.ipv6_cidr_blocks or subnet.ipv6_cidr_block:
        ipv6_enabled = True
    else:
        ipv6_enabled = False
    
    dns_ipv4 = []
    dns_ipv6 = []
    search_domains = []
    if  hasattr(dhcp_opts, "options") and dhcp_opts.options is not None and len(dhcp_opts.options) > 0:
        for option in dhcp_opts.options:
            if option.type == "DomainNameServer":
                if option.serverType == "VcnLocalPlusInternet":
                    dns_ipv4 = [DEFAULT_IPV4_DNS]
                    if ipv6_enabled:
                        dns_ipv6 = [DEFAULT_IPV6_DNS]
                elif option.serverType == "CustomDnsServer":
                    dns_ipv4 = option.customDnsServers
                    if option.vcnResolverConfiguration == 'EnableForVcnAndInternet':
                        dns_ipv4.append(DEFAULT_IPV4_DNS)
                        if ipv6_enabled:
                           dns_ipv6 = [DEFAULT_IPV6_DNS]
            elif option.type == "SearchDomain":
                if dhcp_opts.domainNameType == "SUBNET_DOMAIN":
                    search_domains.append(subnet_search_domain)
                elif dhcp_opts.domainNameType == "VCN_DOMAIN":
                    search_domains.append(vcn_search_domain)
                elif dhcp_opts.domainNameType == "CUSTOM_DOMAIN" and  hasattr(option, "searchDomainNames") and len(option.searchDomainNames) > 0:
                    search_domains = option.searchDomainNames

    return dns_ipv4, dns_ipv6, search_domains

def collect_vnic_info(instance_ocid, compartment_id, compute_client, vn_client):
    """
    Collects VNIC and subnet information from OCI and returns a list of dictionaries with the following keys:
      - isPrimaryVnic: boolean indicating if the VNIC is primary
      - vnic: The VNIC object
      - ipv4_addresses: List of IPv4 addresses (CIDR notation)
      - ipv6_addresses: List of IPv6 addresses (CIDR notation)
      - subnet: The Subnet object for the VNIC
      - dns_ipv4: List of IPv4 DNS addresses
      - dns_ipv6: List of IPv6 DNS addresses
      - search_domains: List of search domains
    """
    vnic_info_list = []
    try:
        vnic_attachments = oci.pagination.list_call_get_all_results(
            compute_client.list_vnic_attachments,
            compartment_id=compartment_id,
            instance_id=instance_ocid
        ).data
    except Exception as e:
        logger.error("Failed to get VNIC attachments: %s", str(e))
        raise

    for attachment in vnic_attachments:
        try:
            if attachment.lifecycle_state != "ATTACHED":
                logger.warning("Skipping VNIC attachment %s with state %s", attachment.id, attachment.lifecycle_state)
                continue

            vnic = vn_client.get_vnic(attachment.vnic_id).data
            subnet = vn_client.get_subnet(vnic.subnet_id).data
            vcn = vn_client.get_vcn(subnet.vcn_id).data
            dhcp_opts = get_dhcp_options(vn_client, subnet.dhcp_options_id)
            dns_ipv4, dns_ipv6, search_domains = get_dns_info(dhcp_opts, subnet, vcn) 
            private_ipv4s = vn_client.list_private_ips(vnic_id=vnic.id).data
            ipv6s = vn_client.list_ipv6s(vnic_id=vnic.id).data
            
            ipv4_addresses = []
            ipv6_addresses = []

            if hasattr(subnet, "cidr_block") and subnet.cidr_block is not None:
                ipv4_net = ipaddress.IPv4Network(subnet.cidr_block, strict=False)
                ipv4_prefix = ipv4_net.prefixlen
                for ipv4 in private_ipv4s:
                    if ipv4.ip_state != "ASSIGNED":
                        continue
                    if ipv4.is_primary: # Insert primary first
                        assert vnic.private_ip == ipv4.ip_address
                        ipv4_addresses.insert(0, f"{ipv4.ip_address}/{ipv4_prefix}") 
                    else:
                        ipv4_addresses.append(f"{ipv4.ip_address}/{ipv4_prefix}")

            if ipv6s is not None and len(ipv6s) > 0:
               for ipv6 in ipv6s:
                    if ipv6.ip_state != "ASSIGNED" or ipv6.lifecycle_state != "AVAILABLE":
                        continue
                    prefix = find_ipv6_prefix(ipv6.ip_address, subnet)
                    prefix = '128' #TODO can we use as per subnet's IPv6 prefix?
                    ipv6_addresses.append(f"{ipv6.ip_address}/{prefix}")

            vnic_info = {
                "isPrimaryVnic": vnic.is_primary,
                "vnic": vnic,
                "ipv4_addresses": ipv4_addresses,
                "ipv6_addresses": ipv6_addresses,
                "subnet": subnet,
                "dns_ipv4": dns_ipv4,
                "dns_ipv6": dns_ipv6,
                "search_domains": search_domains
            }
            if vnic.is_primary:
               vnic_info_list.insert(0, vnic_info) 
            else:
               vnic_info_list.append(vnic_info)

        except Exception as e:
            logger.error("Error processing VNIC attachment %s: %s", attachment.vnic_id, str(e))
            traceback.print_exc()
    return vnic_info_list

def add_routes(iface_config, subnet, table_id=None, metric=100):
    """
    Adds IPv4 and IPv6 routes to the given interface configuration.
    If `table_id` is provided, it is used for policy-based routing.
    """
    if hasattr(subnet, 'virtual_router_ip') and subnet.virtual_router_ip:
        if 'routes' not in iface_config:
            iface_config['routes'] = CommentedSeq()

        default_route = CommentedMap()
        default_route['to'] = "0.0.0.0/0"
        default_route['via'] = subnet.virtual_router_ip
        if table_id:
            default_route['table'] = table_id
        default_route['metric'] = metric
        default_route.yaml_set_start_comment("# IPv4 default route for traffic from this VNIC, via its subnet's IPv4 gateway", indent=8)
        iface_config['routes'].append(default_route)

        link_local_route = CommentedMap()
        link_local_route['to'] = "169.254.0.0/16"
        link_local_route['scope'] = "link"
        if table_id:
            link_local_route['table'] = table_id
        link_local_route['metric'] = metric
        iface_config['routes'].append(link_local_route)

    if hasattr(subnet, 'ipv6_virtual_router_ip') and subnet.ipv6_virtual_router_ip:
        if 'routes' not in iface_config:
            iface_config['routes'] = CommentedSeq()

        ipv6_route = CommentedMap()
        ipv6_route['to'] = "::/0"
        ipv6_route['via'] = subnet.ipv6_virtual_router_ip
        if table_id:
            ipv6_route['table'] = table_id
        ipv6_route['metric'] = metric
        ipv6_route.yaml_set_start_comment("# IPv6 default route for this VNIC, via its subnet's IPv6 gateway", indent=8)
        iface_config['routes'].append(ipv6_route)

def generate_netplan_config(instance_ocid, vnic_info_list, skip_primary=False):
    """
    Generates a netplan YAML configuration from the provided list of VNIC info dictionaries.
    Returns the YAML configuration as a string.
    """
    # Initialize ruamel.yaml with our preferred settings
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    yaml.width = 80  # Line width

    # Create a dictionary with CommentedMap that will be converted to YAML
    netplan_with_comments = CommentedMap()
    netplan_with_comments.yaml_set_start_comment(
        "\n"
        "# Netplan Configuration for Ubuntu compute instances on OCI, auto-generated by ubuntu_netplan_oci.py\n"
        "# This configuration can handle multi-homed setups with multiple VNICs.\n"
        f"# Instance OCID: {instance_ocid}\n"
        "# This file configures all VNICs/network-interfaces. All 2ndary are setup with policy-based routing\n"
        "# Each VNIC is configured with static IPs, DNS, gateways and routing policies used typically for a multihome setup\n"
        "# The configuration uses MAC address matching for each interface\n"
        "# For each VNIC the first IP listed for it below, is its primary IPv4 address\n\n"
    )
    
    network = CommentedMap()
    network['version'] = 2
    network['renderer'] = 'networkd'
    network['ethernets'] = CommentedMap()
    
    netplan_with_comments['network'] = network

    for idx, info in enumerate(vnic_info_list):
        vnic = info["vnic"]
        subnet = info["subnet"]
        interface_name = f"eth{idx}"

        addresses = info["ipv4_addresses"] + info["ipv6_addresses"]

        nw_interface = CommentedMap()
        nw_interface['match'] = CommentedMap({'macaddress': vnic.mac_address})
        nw_interface['dhcp4'] = False
        nw_interface['dhcp6'] = False
        nw_interface['accept-ra'] = False
        nw_interface['addresses'] = addresses # primary IPv4 of a VNIC is always first in the address list.
        nw_interface['mtu'] = 9000  # Enable jumbo frames

        # WARNING: USE netplan yml attribute 'set-name' with caution, 
        # Existing connections might be disrupted when interface names are changed.
        nw_interface['set-name'] = interface_name
        
        nameservers = CommentedMap()
        nameservers['addresses'] = info["dns_ipv4"] + info["dns_ipv6"]
        if info["search_domains"]:
            nameservers['search'] = info["search_domains"]
        
        nw_interface['nameservers'] = nameservers

        # Filter out None values while preserving the CommentedMap
        for key in list(nw_interface.keys()):
            if nw_interface[key] is None:
                del nw_interface[key]

        if info["isPrimaryVnic"]:
            if skip_primary:
                logger.info("Skipping primary VNIC: %s", vnic.id)
                continue

            interface_name = 'etho'
            nw_interface['optional'] = False # Primary VNIC is always required for bootup
            
            comment = (
                f"# Primary VNIC: {vnic.id} \n"
                f"# Connected to Subnet name: {subnet.display_name} \n"
                f"# Subnet OCID: {subnet.id} \n"
                f"# First IP of this primary interface, listed below, is treated as primary/default by convention(when none is spcified by the application) \n"
                f"# All routes for primary VNIC will be in main route table of linux \n"
                f"# All routes for primary VNIC have lower metric than that of all 2ndary VNICs, making them preferred and default \n"
                f"# \n"
            )
            nw_interface.yaml_set_start_comment(comment, indent=6)

            add_routes(nw_interface, subnet, metric=10)

        else:
            # Policy-based routing for secondary VNICs
            nw_interface['optional'] = True 
            comment = (
                f"# Secondary VNIC: {vnic.id}\n"
                f"# Connected to subnet name: {subnet.display_name}\n"
                f"# Subnet OCID: {subnet.id}\n"
                f"# Using policy-based routing with table {100 + idx}\n"
                f"# \n"
            )
            nw_interface.yaml_set_start_comment(comment, indent=6)
            
            table_id = 100 + idx
            routing_policy = CommentedSeq()
            
            for ip_addr in addresses:
                policy = CommentedMap()
                policy['from'] = ip_addr.split("/")[0]
                policy['table'] = table_id
                routing_policy.append(policy)
            
            nw_interface['routing-policy'] = routing_policy

            add_routes(nw_interface, subnet, table_id=table_id, metric=100)
    
        network['ethernets'][interface_name] = nw_interface


    # Configure loopback interface
    lo_config = CommentedMap()
    lo_config['dhcp4'] = False
    lo_config['dhcp6'] = False
    lo_config['addresses'] = ["127.0.0.1/8", "::1/128"]
    lo_config.yaml_set_start_comment("# Loopback interface configuration", indent=6)
    network['ethernets']['lo'] = lo_config

    # Convert the configuration to a YAML string
    from io import StringIO
    string_stream = StringIO()
    yaml.dump(netplan_with_comments, string_stream)
    return string_stream.getvalue()


def write_netplan_config(yaml_string, dest_dir=None):
    """
    Writes the given YAML string to a file or prints it to stdout.
    """
    if dest_dir:
        try:
            if not os.path.isdir(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)
            dest_file = os.path.join(dest_dir, "ubuntu-oci-netplan-config.yaml")
            with open(dest_file, "w") as f:
                f.write(yaml_string)
            logger.info("Netplan configuration written to %s", dest_file)
        except Exception as e:
            logger.error("Failed to write netplan configuration: %s", str(e))
            raise
    else:
        print(yaml_string)

def main():
    parser = argparse.ArgumentParser(description="Generate netplan config for an OCI Ubuntu Compute Instance.")
    parser.add_argument("--instance-ocid", help="OCID of the instance (optional if running on OCI Compute)")
    parser.add_argument("--profile", default="DEFAULT", help="OCI CLI profile name to use from OCI config file (default: DEFAULT)")
    parser.add_argument("--dest-dir", help="Destination directory to write the netplan YAML configuration. If not provided, output is printed to stdout.")
    parser.add_argument("--skip-primary", help="Primary VNIC will be skipped in the netplan config, as OCI supports DHCPv4 and DHCPv6 for it", default=False)
    args = parser.parse_args()

    try:
        instance_ocid = get_instance_ocid(args.instance_ocid)
        config = load_oci_config(args.profile)
        region = extract_region_from_ocid(instance_ocid)
        if config:
            config["region"] = region

        compute_client = get_compute_client(config, region)
        vn_client = get_virtual_network_client(config, region)

        instance = compute_client.get_instance(instance_ocid).data
        compartment_id = instance.compartment_id
        logger.info("Using compartment: %s", compartment_id)

        # First, collect data for all VNICs of the instance.
        vnic_info_list = collect_vnic_info(instance_ocid, compartment_id, compute_client, vn_client)
        # Then generate the netplan configuration from the collected info.
        yaml_string = generate_netplan_config(instance_ocid, vnic_info_list, bool(args.skip_primary))
        write_netplan_config(yaml_string, args.dest_dir)
    except Exception as e:
        logger.error("A fatal error occurred: %s", str(e))
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()