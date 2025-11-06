#!/usr/bin/env python3
"""
Script to list GCP resources: instances, VPCs, and reserved IPs
"""

import os
import sys
from typing import Dict, List, Optional
import argparse

try:
    from google.cloud import compute_v1
    from google.cloud import resourcemanager
    from google.api_core import exceptions as google_exceptions
except ImportError:
    print("Google Cloud libraries not installed. Please install with: pip install google-cloud-compute google-cloud-resource-manager")
    sys.exit(1)

def authenticate_gcp():
    """
    Authenticate to GCP using Application Default Credentials.
    Requires either gcloud auth application-default login or service account key.
    """
    if not os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') and not os.environ.get('GOOGLE_CLOUD_PROJECT'):
        print("Warning: GCP credentials not found. Please set up authentication with one of:")
        print("  1. gcloud auth application-default login")
        print("  2. Set GOOGLE_APPLICATION_CREDENTIALS environment variable to point to a service account key file")
        print("  3. Run with appropriate service account in GCP environment")
        return False
    return True

def list_gcp_instances(project_id: str) -> List[Dict[str, any]]:
    """
    List all GCP compute instances in a given project
    """
    print(f"Listing GCP instances for project: {project_id}")
    instances_client = compute_v1.InstancesClient()
    instances_list = []
    
    try:
        # Get all zones in the project
        zones_client = compute_v1.ZonesClient()
        zones_request = compute_v1.ListZonesRequest(project=project_id)
        zones = zones_client.list(request=zones_request)
        
        for zone in zones:
            request = compute_v1.ListInstancesRequest(
                project=project_id,
                zone=zone.name
            )
            
            page_result = instances_client.list(request=request)
            for instance in page_result:
                instance_info = {
                    'name': instance.name,
                    'zone': zone.name,
                    'status': instance.status,
                    'machine_type': instance.machine_type.split('/')[-1] if instance.machine_type else 'N/A',
                    'internal_ip': [],
                    'external_ip': []
                }
                
                # Extract network interface information
                for interface in instance.network_interfaces:
                    for access_config in interface.access_configs:
                        if access_config.type_ == 'ONE_TO_ONE_NAT':
                            instance_info['external_ip'].append(access_config.nat_i_p)
                    if interface.network_i_p:
                        instance_info['internal_ip'].append(interface.network_i_p)
                
                instances_list.append(instance_info)
        
        print(f"Found {len(instances_list)} instances")
        return instances_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list instances in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing instances: {str(e)}")
        return []

def list_gcp_vpcs(project_id: str) -> List[Dict[str, any]]:
    """
    List all VPC networks in a given project
    """
    print(f"Listing GCP VPC networks for project: {project_id}")
    vpcs_client = compute_v1.NetworksClient()
    vpcs_list = []
    
    try:
        request = compute_v1.ListNetworksRequest(project=project_id)
        page_result = vpcs_client.list(request=request)
        
        for network in page_result:
            network_info = {
                'name': network.name,
                'self_link': network.self_link,
                'description': network.description or 'No description',
                'routing_mode': str(network.routing_config.routing_mode) if network.routing_config else 'N/A',
                'subnetworks': len(network.subnetworks) if network.subnetworks else 0
            }
            vpcs_list.append(network_info)
        
        print(f"Found {len(vpcs_list)} VPC networks")
        return vpcs_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list VPC networks in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing VPCs: {str(e)}")
        return []

def list_gcp_reserved_ips(project_id: str) -> List[Dict[str, any]]:
    """
    List all reserved (static) IP addresses in a given project
    """
    print(f"Listing GCP reserved IPs for project: {project_id}")
    addresses_client = compute_v1.AddressesClient()
    reserved_ips_list = []
    
    try:
        # Get all regions in the project
        regions_client = compute_v1.RegionsClient()
        regions_request = compute_v1.ListRegionsRequest(project=project_id)
        regions = regions_client.list(request=regions_request)
        
        for region in regions:
            request = compute_v1.ListAddressesRequest(
                project=project_id,
                region=region.name
            )
            
            page_result = addresses_client.list(request=request)
            for address in page_result:
                address_info = {
                    'name': address.name,
                    'address': address.address,
                    'region': region.name,
                    'status': address.status.name,
                    'address_type': address.address_type.name,
                    'purpose': address.purpose.name if address.purpose else 'N/A',
                    'subnetwork': address.subnetwork.split('/')[-1] if address.subnetwork else 'N/A'
                }
                reserved_ips_list.append(address_info)
        
        print(f"Found {len(reserved_ips_list)} reserved IP addresses")
        return reserved_ips_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list reserved IPs in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing reserved IPs: {str(e)}")
        return []

def list_gcp_snapshots(project_id: str) -> List[Dict[str, any]]:
    """
    List all GCP compute snapshots in a given project
    """
    print(f"Listing GCP snapshots for project: {project_id}")
    snapshots_client = compute_v1.SnapshotsClient()
    snapshots_list = []
    
    try:
        request = compute_v1.ListSnapshotsRequest(project=project_id)
        page_result = snapshots_client.list(request=request)
        
        for snapshot in page_result:
            snapshot_info = {
                'name': snapshot.name,
                'status': snapshot.status,
                'source_disk': snapshot.source_disk.split('/')[-1] if snapshot.source_disk else 'N/A',
                'storage_bytes': snapshot.storage_bytes,
                'labels': snapshot.labels,
            }
            snapshots_list.append(snapshot_info)
        
        print(f"Found {len(snapshots_list)} snapshots")
        return snapshots_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list snapshots in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing snapshots: {str(e)}")
        return []

def list_gcp_disks(project_id: str) -> List[Dict[str, any]]:
    """
    List all GCP compute disks in a given project
    """
    print(f"Listing GCP disks for project: {project_id}")
    disks_client = compute_v1.DisksClient()
    disks_list = []
    
    try:
        request = compute_v1.AggregatedListDisksRequest(project=project_id)
        page_result = disks_client.aggregated_list(request=request)
        
        for zone, response in page_result:
            if response.disks:
                for disk in response.disks:
                    disk_info = {
                        'name': disk.name,
                        'zone': zone.split('/')[-1],
                        'size_gb': disk.size_gb,
                        'type': disk.type.split('/')[-1],
                        'status': disk.status,
                        'labels': disk.labels,
                    }
                    disks_list.append(disk_info)
        
        print(f"Found {len(disks_list)} disks")
        return disks_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list disks in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing disks: {str(e)}")
        return []

def get_gcp_project_list() -> List[str]:
    """
    Get list of projects accessible by the authenticated user
    """
    try:
        client = resourcemanager.ProjectsClient()
        request = resourcemanager.SearchProjectsRequest()
        page_result = client.search_projects(request=request)
        
        projects = []
        for project in page_result:
            if project.state == resourcemanager.Project.State.ACTIVE:
                projects.append(project.project_id)
        return projects
    except Exception as e:
        print(f"Could not list projects: {str(e)}")
        return []

def print_instances_table(instances: List[Dict[str, any]]) -> None:
    """Print instances in a table format"""
    if not instances:
        print("No instances found.")
        return
    
    print("\nInstances:")
    print(f"{'Name':<30} {'Zone':<20} {'Status':<12} {'Machine Type':<20} {'Internal IPs':<20} {'External IPs':<20}")
    print("-" * 132)
    
    for instance in instances:
        internal_ips = ', '.join(instance['internal_ip'])[:18] + '...' if len(', '.join(instance['internal_ip'])) > 18 else ', '.join(instance['internal_ip'])
        external_ips = ', '.join(instance['external_ip'])[:18] + '...' if len(', '.join(instance['external_ip'])) > 18 else ', '.join(instance['external_ip'])
        print(f"{instance['name']:<30} {instance['zone']:<20} {instance['status']:<12} {instance['machine_type']:<20} {internal_ips:<20} {external_ips:<20}")

def print_vpcs_table(vpcs: List[Dict[str, any]]) -> None:
    """Print VPCs in a table format"""
    if not vpcs:
        print("No VPC networks found.")
        return
    
    print("\nVPC Networks:")
    print(f"{'Name':<30} {'Routing Mode':<15} {'Subnets':<10} {'Description':<50}")
    print("-" * 107)
    
    for vpc in vpcs:
        description = vpc['description'][:47] + '...' if len(vpc['description']) > 47 else vpc['description']
        print(f"{vpc['name']:<30} {vpc['routing_mode']:<15} {vpc['subnetworks']:<10} {description:<50}")

def print_reserved_ips_table(reserved_ips: List[Dict[str, any]]) -> None:
    """Print reserved IPs in a table format"""
    if not reserved_ips:
        print("No reserved IPs found.")
        return
    
    print("\nReserved IPs:")
    print(f"{'Name':<25} {'Address':<15} {'Region':<15} {'Status':<10} {'Type':<10} {'Purpose':<15}")
    print("-" * 92)
    
    for ip in reserved_ips:
        print(f"{ip['name']:<25} {ip['address']:<15} {ip['region']:<15} {ip['status']:<10} {ip['address_type']:<10} {ip['purpose']:<15}")

def print_snapshots_table(snapshots: List[Dict[str, any]]) -> None:
    """Print snapshots in a table format"""
    if not snapshots:
        print("No snapshots found.")
        return
    
    print("\nSnapshots:")
    print(f"{'Name':<30} {'Status':<15} {'Source Disk':<25} {'Size (Bytes)':<15} {'Labels'}")
    print("-" * 120)
    
    for snapshot in snapshots:
        labels = ', '.join([f"{k}={v}" for k, v in snapshot['labels'].items()])
        print(f"{snapshot['name']:<30} {snapshot['status']:<15} {snapshot['source_disk']:<25} {snapshot['storage_bytes']:<15} {labels}")

def print_disks_table(disks: List[Dict[str, any]]) -> None:
    """Print disks in a table format"""
    if not disks:
        print("No disks found.")
        return
    
    print("\nDisks:")
    print(f"{'Name':<30} {'Zone':<20} {'Size (GB)':<10} {'Type':<20} {'Status':<12} {'Labels'}")
    print("-" * 120)
    
    for disk in disks:
        labels = ', '.join([f"{k}={v}" for k, v in disk['labels'].items()])
        print(f"{disk['name']:<30} {disk['zone']:<20} {disk['size_gb']:<10} {disk['type']:<20} {disk['status']:<12} {labels}")

def main():
    parser = argparse.ArgumentParser(description='List GCP resources (instances, VPCs, reserved IPs)')
    parser.add_argument('--project', type=str, help='GCP Project ID. If not specified, will try to list accessible projects')
    parser.add_argument('--instances-only', action='store_true', help='List only instances')
    parser.add_argument('--vpcs-only', action='store_true', help='List only VPC networks')
    parser.add_argument('--ips-only', action='store_true', help='List only reserved IPs')
    parser.add_argument('--snapshots-only', action='store_true', help='List only snapshots with their labels')
    parser.add_argument('--disks-only', action='store_true', help='List only disks with their labels')
    
    args = parser.parse_args()
    
    if not authenticate_gcp():
        print("Exiting due to authentication issues.")
        return 1
    
    # Determine project ID
    project_id = args.project
    if not project_id:
        projects = get_gcp_project_list()
        if not projects:
            print("No projects found or accessible. Please provide a project ID with --project")
            return 1
        elif len(projects) == 1:
            project_id = projects[0]
            print(f"Using project: {project_id}")
        else:
            print(f"Multiple projects found. Available projects: {', '.join(projects)}")
            project_id = input("Enter project ID to use: ").strip()
            if project_id not in projects:
                print(f"Project '{project_id}' not found in your accessible projects.")
                return 1
    
    all_results = {}
    
    list_all = not any([args.instances_only, args.vpcs_only, args.ips_only, args.snapshots_only, args.disks_only])

    if list_all:
        # List all resources
        all_results['instances'] = list_gcp_instances(project_id)
        all_results['vpcs'] = list_gcp_vpcs(project_id)
        all_results['reserved_ips'] = list_gcp_reserved_ips(project_id)
        all_results['snapshots'] = list_gcp_snapshots(project_id)
        all_results['disks'] = list_gcp_disks(project_id)
    else:
        if args.instances_only:
            all_results['instances'] = list_gcp_instances(project_id)
        if args.vpcs_only:
            all_results['vpcs'] = list_gcp_vpcs(project_id)
        if args.ips_only:
            all_results['reserved_ips'] = list_gcp_reserved_ips(project_id)
        if args.snapshots_only:
            all_results['snapshots'] = list_gcp_snapshots(project_id)
        if args.disks_only:
            all_results['disks'] = list_gcp_disks(project_id)
    
    # Print results
    if 'instances' in all_results:
        print_instances_table(all_results['instances'])
    
    if 'vpcs' in all_results:
        print_vpcs_table(all_results['vpcs'])
    
    if 'reserved_ips' in all_results:
        print_reserved_ips_table(all_results['reserved_ips'])

    if 'snapshots' in all_results:
        print_snapshots_table(all_results['snapshots'])

    if 'disks' in all_results:
        print_disks_table(all_results['disks'])
    
    return 0

if __name__ == "__main__":
    sys.exit(main())