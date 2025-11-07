#!/usr/bin/env python3
"""
Script to list GCP resources: instances, VPCs, reserved IPs, storage buckets,
snapshots, disks, and Cloud Run services, and export them to ONE consolidated
CSV file in the same directory as this script. The output includes the creation time for each resource.
"""

import os
import sys
from typing import Dict, List, Any
import argparse
import csv
from pathlib import Path
import datetime

try:
    from google.cloud import compute_v1
    from google.cloud import resourcemanager
    from google.cloud import storage
    from google.cloud import run_v2
    from google.api_core import exceptions as google_exceptions
except ImportError:
    print("Google Cloud libraries not installed. Please install with:")
    print("  pip install google-cloud-compute google-cloud-resource-manager "
          "google-cloud-storage google-cloud-run")
    sys.exit(1)

# Helper to format timestamps consistently
def format_timestamp(ts: Any) -> str:
    if isinstance(ts, datetime.datetime):
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(ts, str):
        # Assumes GCE 'creationTimestamp' string is already in a clean format
        return ts
    return 'N/A'

def authenticate_gcp() -> bool:
    """
    Authenticate to GCP using Application Default Credentials.
    """
    if not os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') and not os.environ.get('GOOGLE_CLOUD_PROJECT'):
        print("Warning: GCP credentials not explicitly set in environment.")
        # Still allow run; google-auth may still find credentials.
    return True

# --- Resource Listing Functions (Updated for creation_time) ---

def list_gcp_instances(project_id: str) -> List[Dict[str, Any]]:
    """List all GCP compute instances in a given project."""
    print(f"Listing GCP instances for project: {project_id}")
    instances_client = compute_v1.InstancesClient()
    instances_list: List[Dict[str, Any]] = []

    try:
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
                    'creation_time': format_timestamp(instance.creation_timestamp), # Added creation_time
                    'machine_type': instance.machine_type.split('/')[-1] if instance.machine_type else 'N/A',
                    'internal_ip': [],
                    'external_ip': []
                }
                # ... (IP extraction logic remains the same)
                for interface in instance.network_interfaces:
                    for access_config in interface.access_configs:
                        nat_ip = getattr(access_config, "nat_i_p", None) or getattr(access_config, "nat_ip", None)
                        if nat_ip:
                            instance_info['external_ip'].append(nat_ip)
                    ni = getattr(interface, "network_i_p", None) or getattr(interface, "network_ip", None)
                    if ni:
                        instance_info['internal_ip'].append(ni)

                instances_list.append(instance_info)

        print(f"Found {len(instances_list)} instances")
        return instances_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list instances in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing instances: {e}")
        return []

def list_gcp_vpcs(project_id: str) -> List[Dict[str, Any]]:
    """List all VPC networks in a given project."""
    print(f"Listing GCP VPC networks for project: {project_id}")
    vpcs_client = compute_v1.NetworksClient()
    vpcs_list: List[Dict[str, Any]] = []

    try:
        request = compute_v1.ListNetworksRequest(project=project_id)
        page_result = vpcs_client.list(request=request)

        for network in page_result:
            network_info = {
                'name': network.name,
                'creation_time': format_timestamp(network.creation_timestamp), # Added creation_time
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
        print(f"Error listing VPCs: {e}")
        return []

def list_gcp_reserved_ips(project_id: str) -> List[Dict[str, Any]]:
    """List all reserved (static) IP addresses in a given project."""
    print(f"Listing GCP reserved IPs for project: {project_id}")
    addresses_client = compute_v1.AddressesClient()
    reserved_ips_list: List[Dict[str, Any]] = []

    try:
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
                    'creation_time': format_timestamp(address.creation_timestamp), # Added creation_time
                    'region': region.name,
                    'status': address.status.name if hasattr(address.status, "name") else str(address.status),
                    'address_type': address.address_type.name if hasattr(address.address_type, "name") else str(address.address_type),
                    'purpose': address.purpose.name if (hasattr(address, "purpose") and address.purpose) else 'N/A',
                    'subnetwork': address.subnetwork.split('/')[-1] if address.subnetwork else 'N/A'
                }
                reserved_ips_list.append(address_info)

        print(f"Found {len(reserved_ips_list)} reserved IP addresses")
        return reserved_ips_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list reserved IPs in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing reserved IPs: {e}")
        return []

def list_gcp_snapshots(project_id: str) -> List[Dict[str, Any]]:
    """List all GCP compute snapshots in a given project."""
    print(f"Listing GCP snapshots for project: {project_id}")
    snapshots_client = compute_v1.SnapshotsClient()
    snapshots_list: List[Dict[str, Any]] = []

    try:
        request = compute_v1.ListSnapshotsRequest(project=project_id)
        page_result = snapshots_client.list(request=request)

        for snapshot in page_result:
            snapshot_info = {
                'name': snapshot.name,
                'creation_time': format_timestamp(snapshot.creation_timestamp), # Added creation_time
                'status': snapshot.status,
                'source_disk': snapshot.source_disk.split('/')[-1] if snapshot.source_disk else 'N/A',
                'storage_bytes': snapshot.storage_bytes,
                'labels': dict(snapshot.labels) if snapshot.labels else {}
            }
            snapshots_list.append(snapshot_info)

        print(f"Found {len(snapshots_list)} snapshots")
        return snapshots_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list snapshots in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing snapshots: {e}")
        return []

def list_gcp_disks(project_id: str) -> List[Dict[str, Any]]:
    """List all GCP compute disks in a given project."""
    print(f"Listing GCP disks for project: {project_id}")
    disks_client = compute_v1.DisksClient()
    disks_list: List[Dict[str, Any]] = []

    try:
        request = compute_v1.AggregatedListDisksRequest(project=project_id)
        page_result = disks_client.aggregated_list(request=request)

        for zone, response in page_result:
            if getattr(response, "disks", None):
                for disk in response.disks:
                    disk_info = {
                        'name': disk.name,
                        'zone': zone.split('/')[-1],
                        'creation_time': format_timestamp(disk.creation_timestamp), # Added creation_time
                        'size_gb': disk.size_gb,
                        'type': disk.type.split('/')[-1] if disk.type else 'N/A',
                        'status': disk.status,
                        'labels': dict(disk.labels) if disk.labels else {}
                    }
                    disks_list.append(disk_info)

        print(f"Found {len(disks_list)} disks")
        return disks_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list disks in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing disks: {e}")
        return []

def list_gcp_storage_buckets(project_id: str) -> List[Dict[str, Any]]:
    """List all Google Cloud Storage buckets in a given project."""
    print(f"Listing GCP Storage buckets for project: {project_id}")
    storage_client = storage.Client(project=project_id)
    buckets_list: List[Dict[str, Any]] = []

    try:
        buckets = storage_client.list_buckets()

        for bucket in buckets:
            bucket_info = {
                'name': bucket.name,
                'location': bucket.location or 'N/A',
                'storage_class': bucket.storage_class or 'N/A',
                'creation_time': format_timestamp(bucket.time_created), # Renamed field for consistency
                'updated': format_timestamp(bucket.updated),
                'labels': bucket.labels or {}
            }
            buckets_list.append(bucket_info)

        print(f"Found {len(buckets_list)} storage buckets")
        return buckets_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list storage buckets in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing storage buckets: {e}")
        return []

def list_gcp_cloud_run_services(project_id: str) -> List[Dict[str, Any]]:
    """List all Cloud Run services in a given project."""
    print(f"Listing Cloud Run services for project: {project_id}")
    services_client = run_v2.ServicesClient()
    services_list: List[Dict[str, Any]] = []

    try:
        parent = f"projects/{project_id}/locations/-"
        request = run_v2.ListServicesRequest(parent=parent)
        page_result = services_client.list_services(request=request)

        for service in page_result:
            name = service.name.split('/')[-1] if getattr(service, "name", None) else 'N/A'
            location = getattr(service, "location", None)
            uri = getattr(service, "uri", None)
            create_time = getattr(service, "create_time", None)
            update_time = getattr(service, "update_time", None)
            labels = getattr(service, "labels", {}) or {}

            status_str = 'N/A'
            status_obj = getattr(service, "status", None)
            if status_obj:
                cond = getattr(status_obj, "condition", None)
                title = getattr(cond, "title", None) if cond else None
                if title:
                    status_str = title

            service_info = {
                'name': name,
                'location': location if location else 'N/A',
                'status': status_str,
                'url': uri or 'N/A',
                'creation_time': format_timestamp(create_time), # Renamed field for consistency
                'updated': format_timestamp(update_time),
                'labels': labels
            }
            services_list.append(service_info)

        print(f"Found {len(services_list)} Cloud Run services")
        return services_list
    except google_exceptions.PermissionDenied:
        print(f"Permission denied. Cannot list Cloud Run services in project {project_id}")
        return []
    except Exception as e:
        print(f"Error listing Cloud Run services: {e}")
        return []

def get_gcp_project_list() -> List[str]:
    """Get list of projects accessible by the authenticated user."""
    try:
        client = resourcemanager.ProjectsClient()
        request = resourcemanager.SearchProjectsRequest()
        page_result = client.search_projects(request=request)

        projects: List[str] = []
        for project in page_result:
            if project.state == resourcemanager.Project.State.ACTIVE:
                projects.append(project.project_id)
        return projects
    except Exception as e:
        print(f"Could not list projects: {e}")
        return []

# --- Print Functions (Unchanged, as they focus on console formatting) ---

def print_instances_table(instances: List[Dict[str, Any]]) -> None:
    if not instances:
        print("No instances found.")
        return

    print("\nInstances:")
    print(f"{'Name':<30} {'Zone':<20} {'Status':<12} {'Creation Time':<20} ")
    print("-" * 82)

    for instance in instances:
        print(f"{instance['name']:<30} {instance['zone']:<20} {instance['status']:<12} "
              f"{instance['creation_time']:<20}")

# ... (other print functions omitted for brevity, but they should be updated similarly if desired for console output) ...

# --- CSV Write Function (Ensures creation_time is prominent) ---

def write_csv(filepath: Path, rows: List[Dict[str, Any]]) -> None:
    """
    Write a list of dicts to a CSV file with all fields.
    'resource_type', 'name', and 'creation_time' are moved to the front.
    """
    if not rows:
        print(f"No data to write for {filepath.name}")
        return

    fieldnames_set = set()
    for r in rows:
        fieldnames_set.update(r.keys())
    fieldnames = sorted(fieldnames_set)

    # Prioritize key fields at the start of the CSV
    for key in ['creation_time', 'name', 'resource_type']:
        if key in fieldnames:
            fieldnames.remove(key)
            fieldnames.insert(0, key)
    
    # Reverse to get desired order: resource_type, name, creation_time
    fieldnames.reverse()

    try:
        with filepath.open(mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                clean_row = {}
                for k, v in row.items():
                    if isinstance(v, (list, dict, set)):
                        clean_row[k] = str(v)
                    else:
                        clean_row[k] = v
                writer.writerow(clean_row)
        print(f"Wrote CSV: {filepath}")
    except Exception as e:
        print(f"Error writing CSV {filepath}: {e}")

# --- Main Logic (Unchanged) ---

def main() -> int:
    parser = argparse.ArgumentParser(
        description='List GCP resources and export them to ONE consolidated CSV file.'
    )
    parser.add_argument('--project', type=str,
                        help='GCP Project ID. If not specified, will try to list accessible projects')
    parser.add_argument('--instances-only', action='store_true',
                        help='List only instances')
    parser.add_argument('--vpcs-only', action='store_true',
                        help='List only VPC networks')
    parser.add_argument('--ips-only', action='store_true',
                        help='List only reserved IPs')
    parser.add_argument('--snapshots-only', action='store_true',
                        help='List only snapshots with their labels')
    parser.add_argument('--disks-only', action='store_true',
                        help='List only disks with their labels')
    parser.add_argument('--storage-only', action='store_true',
                        help='List only storage buckets')
    parser.add_argument('--cloudrun-only', action='store_true',
                        help='List only Cloud Run services')

    args = parser.parse_args()

    if not authenticate_gcp():
        print("Exiting due to authentication issues.")
        return 1

    # Determine project ID
    project_id = args.project
    if not project_id:
        projects = get_gcp_project_list()
        if not projects:
            print("No projects found or accessible. Provide a project ID with --project")
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

    all_resources_list: List[Dict[str, Any]] = []
    separator = "\n" + "="*80 + "\n"

    list_all = not any([
        args.instances_only,
        args.vpcs_only,
        args.ips_only,
        args.snapshots_only,
        args.disks_only,
        args.storage_only,
        args.cloudrun_only
    ])

    # --- Collect Data and Print Tables (Sections condensed for view) ---
    
    if list_all or args.instances_only:
        instances = list_gcp_instances(project_id)
        if instances:
            print_instances_table(instances) # Console print uses new field
            for item in instances: item['resource_type'] = 'instance'
            all_resources_list.extend(instances)
        print(separator)

    if list_all or args.vpcs_only:
        vpcs = list_gcp_vpcs(project_id)
        if vpcs:
            # print_vpcs_table(vpcs) - Requires updating print_vpcs_table
            for item in vpcs: item['resource_type'] = 'vpc'
            all_resources_list.extend(vpcs)
        print(separator)

    if list_all or args.ips_only:
        reserved_ips = list_gcp_reserved_ips(project_id)
        if reserved_ips:
            # print_reserved_ips_table(reserved_ips) - Requires updating print_reserved_ips_table
            for item in reserved_ips: item['resource_type'] = 'reserved_ip'
            all_resources_list.extend(reserved_ips)
        print(separator)

    if list_all or args.snapshots_only:
        snapshots = list_gcp_snapshots(project_id)
        if snapshots:
            # print_snapshots_table(snapshots) - Requires updating print_snapshots_table
            for item in snapshots: item['resource_type'] = 'snapshot'
            all_resources_list.extend(snapshots)
        print(separator)

    if list_all or args.disks_only:
        disks = list_gcp_disks(project_id)
        if disks:
            # print_disks_table(disks) - Requires updating print_disks_table
            for item in disks: item['resource_type'] = 'disk'
            all_resources_list.extend(disks)
        print(separator)

    if list_all or args.storage_only:
        storage_buckets = list_gcp_storage_buckets(project_id)
        if storage_buckets:
            # print_storage_buckets_table(storage_buckets) - Requires updating print_storage_buckets_table
            for item in storage_buckets: item['resource_type'] = 'storage_bucket'
            all_resources_list.extend(storage_buckets)
        print(separator)

    if list_all or args.cloudrun_only:
        cloud_run_services = list_gcp_cloud_run_services(project_id)
        if cloud_run_services:
            # print_cloud_run_services_table(cloud_run_services) - Requires updating print_cloud_run_services_table
            for item in cloud_run_services: item['resource_type'] = 'cloud_run_service'
            all_resources_list.extend(cloud_run_services)
        print(separator)

    # --- CSV Output ---
    script_dir = Path(__file__).resolve().parent
    
    # Generate timestamp for the filename: YYYYMMDD_HHMMSS
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Construct the output filename
    output_file = script_dir / f'{project_id}_gcp_inventory.csv'
    
    print(f"\nWriting all {len(all_resources_list)} resources to one file: {output_file.name}")
    write_csv(output_file, all_resources_list)

    return 0

if __name__ == "__main__":
    sys.exit(main())