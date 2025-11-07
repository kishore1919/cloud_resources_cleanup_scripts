#!/usr/bin/env python3
"""
Script to list GCP resources: instances, VPCs, reserved IPs, storage buckets,
snapshots, disks, and Cloud Run services, and export them to CSV files
in the same directory as this script.
"""

import os
import sys
from typing import Dict, List, Any
import argparse
import csv
from pathlib import Path

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

def authenticate_gcp() -> bool:
    """
    Authenticate to GCP using Application Default Credentials.
    This is a light pre-check; actual ADC resolution is handled by the libraries.
    """
    if not os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') and not os.environ.get('GOOGLE_CLOUD_PROJECT'):
        print("Warning: GCP credentials not explicitly set in environment.")
        print("Ensure one of the following is set up before running:")
        print("  1. gcloud auth application-default login")
        print("  2. Set GOOGLE_APPLICATION_CREDENTIALS to a service account key file")
        print("  3. Run in GCP with an attached service account")
        # Still allow run; google-auth may still find credentials.
    return True

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
                    'machine_type': instance.machine_type.split('/')[-1] if instance.machine_type else 'N/A',
                    'internal_ip': [],
                    'external_ip': []
                }

                # Extract network interface information
                for interface in instance.network_interfaces:
                    # External IPs
                    for access_config in interface.access_configs:
                        nat_ip = getattr(access_config, "nat_i_p", None) or getattr(access_config, "nat_ip", None)
                        if nat_ip:
                            instance_info['external_ip'].append(nat_ip)

                    # Internal IP
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
                'created': bucket.time_created.strftime('%Y-%m-%d %H:%M:%S') if bucket.time_created else 'N/A',
                'updated': bucket.updated.strftime('%Y-%m-%d %H:%M:%S') if bucket.updated else 'N/A',
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
                'created': create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else 'N/A',
                'updated': update_time.strftime('%Y-%m-%d %H:%M:%S') if update_time else 'N/A',
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

def print_instances_table(instances: List[Dict[str, Any]]) -> None:
    if not instances:
        print("No instances found.")
        return

    print("\nInstances:")
    print(f"{'Name':<30} {'Zone':<20} {'Status':<12} {'Machine Type':<20} "
          f"{'Internal IPs':<20} {'External IPs':<20}")
    print("-" * 132)

    for instance in instances:
        internal_joined = ', '.join(instance['internal_ip'])
        external_joined = ', '.join(instance['external_ip'])
        internal_ips = (internal_joined[:18] + '...') if len(internal_joined) > 18 else internal_joined
        external_ips = (external_joined[:18] + '...') if len(external_joined) > 18 else external_joined

        print(f"{instance['name']:<30} {instance['zone']:<20} {instance['status']:<12} "
              f"{instance['machine_type']:<20} {internal_ips:<20} {external_ips:<20}")

def print_vpcs_table(vpcs: List[Dict[str, Any]]) -> None:
    if not vpcs:
        print("No VPC networks found.")
        return

    print("\nVPC Networks:")
    print(f"{'Name':<30} {'Routing Mode':<15} {'Subnets':<10} {'Description':<50}")
    print("-" * 107)

    for vpc in vpcs:
        description = vpc['description']
        if len(description) > 47:
            description = description[:47] + '...'
        print(f"{vpc['name']:<30} {vpc['routing_mode']:<15} "
              f"{vpc['subnetworks']:<10} {description:<50}")

def print_reserved_ips_table(reserved_ips: List[Dict[str, Any]]) -> None:
    if not reserved_ips:
        print("No reserved IPs found.")
        return

    print("\nReserved IPs:")
    print(f"{'Name':<25} {'Address':<15} {'Region':<15} "
          f"{'Status':<10} {'Type':<10} {'Purpose':<15}")
    print("-" * 92)

    for ip in reserved_ips:
        print(f"{ip['name']:<25} {ip['address']:<15} {ip['region']:<15} "
              f"{ip['status']:<10} {ip['address_type']:<10} {ip['purpose']:<15}")

def print_snapshots_table(snapshots: List[Dict[str, Any]]) -> None:
    if not snapshots:
        print("No snapshots found.")
        return

    print("\nSnapshots:")
    print(f"{'Name':<30} {'Status':<15} {'Source Disk':<25} "
          f"{'Size (Bytes)':<15} {'Labels'}")
    print("-" * 120)

    for snapshot in snapshots:
        labels = ', '.join([f"{k}={v}" for k, v in snapshot['labels'].items()])
        print(f"{snapshot['name']:<30} {snapshot['status']:<15} "
              f"{snapshot['source_disk']:<25} {snapshot['storage_bytes']:<15} {labels}")

def print_disks_table(disks: List[Dict[str, Any]]) -> None:
    if not disks:
        print("No disks found.")
        return

    print("\nDisks:")
    print(f"{'Name':<30} {'Zone':<20} {'Size (GB)':<10} "
          f"{'Type':<20} {'Status':<12} {'Labels'}")
    print("-" * 120)

    for disk in disks:
        labels = ', '.join([f"{k}={v}" for k, v in disk['labels'].items()])
        print(f"{disk['name']:<30} {disk['zone']:<20} {disk['size_gb']:<10} "
              f"{disk['type']:<20} {disk['status']:<12} {labels}")

def print_storage_buckets_table(buckets: List[Dict[str, Any]]) -> None:
    if not buckets:
        print("No storage buckets found.")
        return

    print("\nStorage Buckets:")
    print(f"{'Name':<40} {'Location':<15} {'Storage Class':<15} "
          f"{'Created':<20} {'Labels'}")
    print("-" * 120)

    for bucket in buckets:
        labels = ', '.join([f"{k}={v}" for k, v in bucket['labels'].items()])
        print(f"{bucket['name']:<40} {bucket['location']:<15} "
              f"{bucket['storage_class']:<15} {bucket['created']:<20} {labels}")

def print_cloud_run_services_table(services: List[Dict[str, Any]]) -> None:
    if not services:
        print("No Cloud Run services found.")
        return

    print("\nCloud Run Services:")
    print(f"{'Name':<30} {'Location':<15} {'Status':<15} "
          f"{'URL':<50} {'Created':<20}")
    print("-" * 150)

    for service in services:
        url = service['url']
        if len(url) > 47:
            url = url[:47] + '...'
        print(f"{service['name']:<30} {service['location']:<15} "
              f"{service['status']:<15} {url:<50} {service['created']:<20}")

def write_csv(filepath: Path, rows: List[Dict[str, Any]]) -> None:
    """
    Write a list of dicts to a CSV file with all fields.
    Lists/dicts are stringified so all details are preserved.
    """
    if not rows:
        print(f"No data to write for {filepath.name}")
        return

    # Gather all keys across all rows
    fieldnames_set = set()
    for r in rows:
        fieldnames_set.update(r.keys())
    fieldnames = sorted(fieldnames_set)

    try:
        with filepath.open(mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                clean_row = {}
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        clean_row[k] = str(v)
                    else:
                        clean_row[k] = v
                writer.writerow(clean_row)
        print(f"Wrote CSV: {filepath}")
    except Exception as e:
        print(f"Error writing CSV {filepath}: {e}")

def main() -> int:
    parser = argparse.ArgumentParser(
        description='List GCP resources and export them to CSV files (same dir as this script).'
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

    all_results: Dict[str, List[Dict[str, Any]]] = {}

    list_all = not any([
        args.instances_only,
        args.vpcs_only,
        args.ips_only,
        args.snapshots_only,
        args.disks_only,
        args.storage_only,
        args.cloudrun_only
    ])

    # Collect data
    if list_all:
        all_results['instances'] = list_gcp_instances(project_id)
        all_results['vpcs'] = list_gcp_vpcs(project_id)
        all_results['reserved_ips'] = list_gcp_reserved_ips(project_id)
        all_results['snapshots'] = list_gcp_snapshots(project_id)
        all_results['disks'] = list_gcp_disks(project_id)
        all_results['storage_buckets'] = list_gcp_storage_buckets(project_id)
        all_results['cloud_run_services'] = list_gcp_cloud_run_services(project_id)
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
        if args.storage_only:
            all_results['storage_buckets'] = list_gcp_storage_buckets(project_id)
        if args.cloudrun_only:
            all_results['cloud_run_services'] = list_gcp_cloud_run_services(project_id)

    # Print tables
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
    if 'storage_buckets' in all_results:
        print_storage_buckets_table(all_results['storage_buckets'])
    if 'cloud_run_services' in all_results:
        print_cloud_run_services_table(all_results['cloud_run_services'])

    # CSV output directory: same directory as this script
    script_dir = Path(__file__).resolve().parent

    # Write CSVs
    if 'instances' in all_results:
        write_csv(script_dir / 'instances.csv', all_results['instances'])
    if 'vpcs' in all_results:
        write_csv(script_dir / 'vpcs.csv', all_results['vpcs'])
    if 'reserved_ips' in all_results:
        write_csv(script_dir / 'reserved_ips.csv', all_results['reserved_ips'])
    if 'snapshots' in all_results:
        write_csv(script_dir / 'snapshots.csv', all_results['snapshots'])
    if 'disks' in all_results:
        write_csv(script_dir / 'disks.csv', all_results['disks'])
    if 'storage_buckets' in all_results:
        write_csv(script_dir / 'storage_buckets.csv', all_results['storage_buckets'])
    if 'cloud_run_services' in all_results:
        write_csv(script_dir / 'cloud_run_services.csv', all_results['cloud_run_services'])

    return 0

if __name__ == "__main__":
    sys.exit(main())