#!/usr/bin/env python3
"""
Script to list AWS resources: EC2 instances, VPCs, S3 buckets, RDS instances,
Lambda functions, and many other AWS resources, and export them to ONE consolidated
CSV file in the same directory as this script. The output includes the creation time for each resource.
"""

import os
import sys
from typing import Dict, List, Any
import argparse
import csv
from pathlib import Path
import datetime
import json
import boto3

try:
    import boto3
except ImportError:
    print("AWS Boto3 library not installed. Please install with:")
    print("  pip install boto3")
    sys.exit(1)

try:
    import click
except ImportError:
    print("Click library not installed. Please install with:")
    print("  pip install click")
    sys.exit(1)

# Resource types supported by the AWS lister
ALL_RESOURCE_TYPES = [
    'ec2_instances',
    'ec2_volumes', 
    'ec2_snapshots',
    's3_buckets',
    'lambda_functions',
    'rds_instances',
    'ecs_clusters',
    'security_groups',
    'vpcs'
]

# Helper to format timestamps consistently
def format_timestamp(ts: Any) -> str:
    if isinstance(ts, datetime.datetime):
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(ts, str):
        return ts
    return 'N/A'

def authenticate_aws() -> bool:
    """
    Authenticate to AWS using default credentials.
    """
    try:
        sts_client = boto3.client('sts')
        sts_client.get_caller_identity()
        return True
    except Exception:
        print("Warning: AWS credentials not found. Please configure AWS CLI or environment variables.")
        return False

# --- Resource Listing Functions ---

def list_aws_instances() -> List[Dict[str, Any]]:
    """List all EC2 instances across all regions."""
    print("Listing AWS EC2 instances")
    instances_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                paginator = ec2_client.get_paginator('describe_instances')
                
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            if instance['State']['Name'] in ['terminated', 'terminating']:
                                continue
                            
                            # Extract tags
                            tags = instance.get('Tags', [])
                            name = 'N/A'
                            for tag in tags:
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break

                            instance_info = {
                                'name': name,
                                'region': region,
                                'status': instance['State']['Name'],
                                'creation_time': format_timestamp(instance['LaunchTime']),
                                'instance_type': instance['InstanceType'],
                                'instance_id': instance['InstanceId'],
                                'vpc_id': instance.get('VpcId', 'N/A'),
                                'subnet_id': instance.get('SubnetId', 'N/A'),
                                'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                                'public_ip': instance.get('PublicIpAddress', 'N/A'),
                                'key_name': instance.get('KeyName', 'N/A'),
                                'tags': ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                            }
                            instances_list.append(instance_info)
            except Exception as e:
                print(f"Error listing instances in region {region}: {e}")
                continue

        print(f"Found {len(instances_list)} instances")
        return instances_list
    except Exception as e:
        print(f"Error listing instances: {e}")
        return []

def list_aws_vpcs() -> List[Dict[str, Any]]:
    """List all VPC networks across all regions."""
    print("Listing AWS VPC networks")
    vpcs_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                response = ec2_client.describe_vpcs()
                
                for vpc in response['Vpcs']:
                    if vpc.get('IsDefault', False):
                        continue
                    
                    # Extract tags
                    tags = vpc.get('Tags', [])
                    name = 'N/A'
                    for tag in tags:
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break

                    vpc_info = {
                        'name': name,
                        'region': region,
                        'vpc_id': vpc['VpcId'],
                        'cidr_block': vpc['CidrBlock'],
                        'state': vpc['State'],
                        'creation_time': 'N/A', # VPCs don't have creation timestamp
                        'description': vpc.get('Description', 'N/A'),
                        'tags': ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                    }
                    vpcs_list.append(vpc_info)
            except Exception as e:
                print(f"Error listing VPCs in region {region}: {e}")
                continue

        print(f"Found {len(vpcs_list)} VPC networks")
        return vpcs_list
    except Exception as e:
        print(f"Error listing VPCs: {e}")
        return []

def list_aws_s3_buckets() -> List[Dict[str, Any]]:
    """List all S3 buckets."""
    print("Listing AWS S3 buckets")
    buckets_list: List[Dict[str, Any]] = []

    try:
        s3_client = boto3.client('s3', region_name='us-east-1')
        response = s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            try:
                bucket_location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                region = bucket_location['LocationConstraint'] or 'us-east-1'
                
                # Get bucket tags
                try:
                    tagging = s3_client.get_bucket_tagging(Bucket=bucket['Name'])
                    tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tagging.get('TagSet', [])])
                except:
                    tags = 'N/A'

                bucket_info = {
                    'name': bucket['Name'],
                    'region': region,
                    'creation_time': format_timestamp(bucket['CreationDate']),
                    'location': region,
                    'bucket_id': bucket['Name'],
                    'tags': tags
                }
                buckets_list.append(bucket_info)
            except Exception as e:
                print(f"Error getting details for bucket {bucket['Name']}: {e}")
                continue

        print(f"Found {len(buckets_list)} S3 buckets")
        return buckets_list
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
        return []

def list_aws_rds_instances() -> List[Dict[str, Any]]:
    """List all RDS instances across all regions."""
    print("Listing AWS RDS instances")
    rds_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                rds_client = boto3.client('rds', region_name=region)
                paginator = rds_client.get_paginator('describe_db_instances')
                
                for page in paginator.paginate():
                    for db_instance in page['DbInstances']:
                        # Extract tags
                        try:
                            tags_response = rds_client.list_tags_for_resource(ResourceName=db_instance['DBInstanceArn'])
                            tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags_response.get('TagList', [])])
                        except:
                            tags = 'N/A'

                        rds_info = {
                            'name': db_instance['DBInstanceIdentifier'],
                            'region': region,
                            'status': db_instance['DBInstanceStatus'],
                            'creation_time': format_timestamp(db_instance['InstanceCreateTime']),
                            'db_instance_id': db_instance['DBInstanceIdentifier'],
                            'engine': db_instance['Engine'],
                            'engine_version': db_instance['EngineVersion'],
                            'instance_class': db_instance['DBInstanceClass'],
                            'storage_gb': db_instance['AllocatedStorage'],
                            'vpc_id': db_instance.get('DBSubnetGroup', {}).get('VpcId', 'N/A'),
                            'tags': tags
                        }
                        rds_list.append(rds_info)
            except Exception as e:
                print(f"Error listing RDS instances in region {region}: {e}")
                continue

        print(f"Found {len(rds_list)} RDS instances")
        return rds_list
    except Exception as e:
        print(f"Error listing RDS instances: {e}")
        return []

def list_aws_lambda_functions() -> List[Dict[str, Any]]:
    """List all Lambda functions across all regions."""
    print("Listing AWS Lambda functions")
    lambda_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                lambda_client = boto3.client('lambda', region_name=region)
                paginator = lambda_client.get_paginator('list_functions')
                
                for page in paginator.paginate():
                    for function in page['Functions']:
                        # Get function tags
                        try:
                            tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                            tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags_response.get('Tags', {}).items()])
                        except:
                            tags = 'N/A'

                        lambda_info = {
                            'name': function['FunctionName'],
                            'region': region,
                            'status': 'N/A', # Lambda doesn't have a simple status
                            'creation_time': format_timestamp(function.get('LastModified', 'N/A')),
                            'function_name': function['FunctionName'],
                            'runtime': function['Runtime'],
                            'handler': function['Handler'],
                            'code_size_mb': round(function['CodeSize'] / 1024 / 1024, 2),
                            'memory_mb': function['MemorySize'],
                            'timeout_sec': function['Timeout'],
                            'tags': tags
                        }
                        lambda_list.append(lambda_info)
            except Exception as e:
                print(f"Error listing Lambda functions in region {region}: {e}")
                continue

        print(f"Found {len(lambda_list)} Lambda functions")
        return lambda_list
    except Exception as e:
        print(f"Error listing Lambda functions: {e}")
        return []

def list_aws_security_groups() -> List[Dict[str, Any]]:
    """List all security groups across all regions."""
    print("Listing AWS security groups")
    sg_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                paginator = ec2_client.get_paginator('describe_security_groups')
                
                for page in paginator.paginate():
                    for sg in page['SecurityGroups']:
                        if sg['GroupName'] == 'default':
                            continue
                        
                        # Extract tags
                        tags = sg.get('Tags', [])
                        name = sg['GroupName']
                        for tag in tags:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break

                        sg_info = {
                            'name': name,
                            'region': region,
                            'status': 'N/A',
                            'creation_time': 'N/A',
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'description': sg['Description'],
                            'vpc_id': sg.get('VpcId', 'N/A'),
                            'tags': ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                        }
                        sg_list.append(sg_info)
            except Exception as e:
                print(f"Error listing security groups in region {region}: {e}")
                continue

        print(f"Found {len(sg_list)} security groups")
        return sg_list
    except Exception as e:
        print(f"Error listing security groups: {e}")
        return []

def list_aws_volumes() -> List[Dict[str, Any]]:
    """List all EBS volumes across all regions."""
    print("Listing AWS EBS volumes")
    volumes_list: List[Dict[str, Any]] = []

    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

        for region in regions:
            try:
                ec2_client = boto3.client('ec2', region_name=region)
                paginator = ec2_client.get_paginator('describe_volumes')
                
                for page in paginator.paginate():
                    for volume in page['Volumes']:
                        # Extract tags
                        tags = volume.get('Tags', [])
                        name = 'N/A'
                        for tag in tags:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break

                        volume_info = {
                            'name': name,
                            'region': region,
                            'status': volume['State'],
                            'creation_time': format_timestamp(volume['CreateTime']),
                            'volume_id': volume['VolumeId'],
                            'size_gb': volume['Size'],
                            'volume_type': volume['VolumeType'],
                            'availability_zone': volume['AvailabilityZone'],
                            'encrypted': volume['Encrypted'],
                            'tags': ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                        }
                        volumes_list.append(volume_info)
            except Exception as e:
                print(f"Error listing volumes in region {region}: {e}")
                continue

        print(f"Found {len(volumes_list)} EBS volumes")
        return volumes_list
    except Exception as e:
        print(f"Error listing volumes: {e}")
        return []

# --- Print Functions ---

def print_instances_table(instances: List[Dict[str, Any]]) -> None:
    if not instances:
        print("No instances found.")
        return

    print("\nInstances:")
    print(f"{'Name':<30} {'Region':<15} {'Status':<12} {'Type':<15} {'ID':<15}")
    print("-" * 87)

    for instance in instances:
        print(f"{instance['name']:<30} {instance['region']:<15} {instance['status']:<12} {instance['instance_type']:<15} {instance['instance_id']:<15}")

def print_vpcs_table(vpcs: List[Dict[str, Any]]) -> None:
    if not vpcs:
        print("No VPCs found.")
        return

    print("\nVPCs:")
    print(f"{'Name':<30} {'Region':<15} {'VPC ID':<15} {'CIDR Block':<15}")
    print("-" * 75)

    for vpc in vpcs:
        print(f"{vpc['name']:<30} {vpc['region']:<15} {vpc['vpc_id']:<15} {vpc['cidr_block']:<15}")

# --- CSV Write Function ---

def write_csv(filepath: Path, rows: List[Dict[str, Any]]) -> None:
    """
    Write a list of dicts to a CSV file with all fields.
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
    
    # Reverse to get desired order
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

# --- Main Logic ---

def main() -> int:
    parser = argparse.ArgumentParser(
        description='List AWS resources and export them to ONE consolidated CSV file.'
    )
    parser.add_argument('--instances-only', action='store_true',
                        help='List only instances')
    parser.add_argument('--vpcs-only', action='store_true',
                        help='List only VPC networks')
    parser.add_argument('--s3-only', action='store_true',
                        help='List only S3 buckets')
    parser.add_argument('--rds-only', action='store_true',
                        help='List only RDS instances')
    parser.add_argument('--lambda-only', action='store_true',
                        help='List only Lambda functions')
    parser.add_argument('--security-groups-only', action='store_true',
                        help='List only security groups')
    parser.add_argument('--volumes-only', action='store_true',
                        help='List only EBS volumes')

    args = parser.parse_args()

    if not authenticate_aws():
        print("Exiting due to authentication issues.")
        return 1

    all_resources_list: List[Dict[str, Any]] = []
    separator = "\n" + "="*80 + "\n"

    list_all = not any([
        args.instances_only,
        args.vpcs_only,
        args.s3_only,
        args.rds_only,
        args.lambda_only,
        args.security_groups_only,
        args.volumes_only
    ])

    # --- Collect Data and Print Tables ---
    
    if list_all or args.instances_only:
        instances = list_aws_instances()
        if instances:
            print_instances_table(instances)
            for item in instances: item['resource_type'] = 'ec2_instance'
            all_resources_list.extend(instances)
        print(separator)

    if list_all or args.vpcs_only:
        vpcs = list_aws_vpcs()
        if vpcs:
            print_vpcs_table(vpcs)
            for item in vpcs: item['resource_type'] = 'vpc'
            all_resources_list.extend(vpcs)
        print(separator)

    if list_all or args.s3_only:
        s3_buckets = list_aws_s3_buckets()
        if s3_buckets:
            for item in s3_buckets: item['resource_type'] = 's3_bucket'
            all_resources_list.extend(s3_buckets)
        print(separator)

    if list_all or args.rds_only:
        rds_instances = list_aws_rds_instances()
        if rds_instances:
            for item in rds_instances: item['resource_type'] = 'rds_instance'
            all_resources_list.extend(rds_instances)
        print(separator)

    if list_all or args.lambda_only:
        lambda_functions = list_aws_lambda_functions()
        if lambda_functions:
            for item in lambda_functions: item['resource_type'] = 'lambda_function'
            all_resources_list.extend(lambda_functions)
        print(separator)

    if list_all or args.security_groups_only:
        security_groups = list_aws_security_groups()
        if security_groups:
            for item in security_groups: item['resource_type'] = 'security_group'
            all_resources_list.extend(security_groups)
        print(separator)

    if list_all or args.volumes_only:
        volumes = list_aws_volumes()
        if volumes:
            for item in volumes: item['resource_type'] = 'ebs_volume'
            all_resources_list.extend(volumes)
        print(separator)

    # --- CSV Output ---
    script_dir = Path(__file__).resolve().parent
    
    # Generate timestamp for the filename: YYYYMMDD_HHMMSS
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Construct the output filename
    output_file = script_dir / f'aws_inventory.csv'
    
    print(f"\nWriting all {len(all_resources_list)} resources to one file: {output_file.name}")
    write_csv(output_file, all_resources_list)

    return 0

if __name__ == "__main__":
    sys.exit(main())
    
    def list_ec2_instances(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing EC2 instances in region: {region}")
        ec2_resource = boto3.resource('ec2', region_name=region)
        instances_out = []
        try:
            for instance in ec2_resource.instances.all():
                if instance.state['Name'] in ['terminated', 'terminating']:
                    continue
                
                tags_list = instance.tags or []
                instance_name = self._extract_name_from_tags(tags_list)
                
                details = {
                    "instance_type": instance.instance_type,
                    "public_ip": instance.public_ip_address or 'N/A',
                    "private_ip": instance.private_ip_address or 'N/A',
                    "vpc_id": instance.vpc_id or 'N/A',
                    "subnet_id": instance.subnet_id or 'N/A',
                    "image_id": instance.image_id or 'N/A',
                    "key_name": instance.key_name or 'N/A',
                    "tags": self._get_tags_str_from_list(tags_list)
                }
                
                instances_out.append({
                    'Region': region,
                    'ResourceType': 'EC2 Instance',
                    'ID': instance.id,
                    'Name': instance_name,
                    'State': instance.state['Name'],
                    'Details': json.dumps(details),
                    'CreationDate': instance.launch_time.isoformat() if instance.launch_time else 'N/A'
                })
        except Exception as e:
            logger.error(f"Error listing EC2 instances in region {region}: {e}")
        return instances_out
    
    def list_ec2_volumes(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing EC2 volumes in region: {region}")
        ec2_resource = boto3.resource('ec2', region_name=region)
        volumes_out = []
        try:
            for volume in ec2_resource.volumes.all():
                tags_list = volume.tags or []
                volume_name = self._extract_name_from_tags(tags_list)
                
                details = {
                    "size_gb": volume.size,
                    "volume_type": volume.volume_type,
                    "availability_zone": volume.availability_zone,
                    "encrypted": volume.encrypted,
                    "iops": volume.iops if volume.iops else 'N/A',
                    "throughput": volume.throughput if volume.throughput else 'N/A',
                    "tags": self._get_tags_str_from_list(tags_list)
                }

                volumes_out.append({
                    'Region': region,
                    'ResourceType': 'EC2 Volume',
                    'ID': volume.id,
                    'Name': volume_name,
                    'State': volume.state,
                    'Details': json.dumps(details),
                    'CreationDate': volume.create_time.isoformat() if volume.create_time else 'N/A'
                })
        except Exception as e:
            logger.error(f"Error listing EC2 volumes in region {region}: {e}")
        return volumes_out
    
    def list_ec2_amis(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing EC2 AMIs in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        amis_out = []
        try:
            response = ec2_client.describe_images(Owners=['self'])
            for ami in response['Images']:
                tags_list = ami.get('Tags', [])
                ami_name_tag = self._extract_name_from_tags(tags_list)
                # AMI 'Name' is a direct property, use tag first, then property
                ami_name = ami_name_tag if ami_name_tag != 'N/A' else ami.get('Name', 'N/A')
                
                details = {
                    "description": ami.get('Description', 'N/A'),
                    "public": ami['Public'],
                    "image_type": ami['ImageType'],
                    "root_device_type": ami['RootDeviceType'],
                    "virtualization_type": ami['VirtualizationType'],
                    "tags": self._get_tags_str_from_list(tags_list)
                }

                amis_out.append({
                    'Region': region,
                    'ResourceType': 'EC2 AMI',
                    'ID': ami['ImageId'],
                    'Name': ami_name,
                    'State': ami['State'],
                    'Details': json.dumps(details),
                    'CreationDate': ami.get('CreationDate', 'N/A')
                })
        except Exception as e:
            logger.error(f"Error listing EC2 AMIs in region {region}: {e}")
        return amis_out

    def list_ec2_snapshots(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing EC2 snapshots in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        snapshots_out = []
        try:
            paginator = ec2_client.get_paginator('describe_snapshots')
            for page in paginator.paginate(OwnerIds=['self']):
                for snapshot in page['Snapshots']:
                    tags_list = snapshot.get('Tags', [])
                    snapshot_name = self._extract_name_from_tags(tags_list)

                    details = {
                        "volume_id": snapshot['VolumeId'],
                        "volume_size_gb": snapshot['VolumeSize'],
                        "description": snapshot['Description'],
                        "encrypted": snapshot['Encrypted'],
                        "owner_id": snapshot['OwnerId'],
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    snapshots_out.append({
                        'Region': region,
                        'ResourceType': 'EC2 Snapshot',
                        'ID': snapshot['SnapshotId'],
                        'Name': snapshot_name,
                        'State': snapshot['State'],
                        'Details': json.dumps(details),
                        'CreationDate': snapshot['StartTime'].isoformat() if snapshot.get('StartTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing EC2 snapshots in region {region}: {e}")
        return snapshots_out

    def list_ec2_key_pairs(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing EC2 Key Pairs in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        key_pairs_out = []
        try:
            response = ec2_client.describe_key_pairs()
            for kp in response['KeyPairs']:
                tags_list = kp.get('Tags', [])
                key_name = kp.get('KeyName', 'N/A') # Name is primary ID here

                details = {
                    "fingerprint": kp.get('KeyFingerprint', 'N/A'),
                    "key_pair_id": kp['KeyPairId'],
                    "tags": self._get_tags_str_from_list(tags_list)
                }

                key_pairs_out.append({
                    'Region': region,
                    'ResourceType': 'EC2 Key Pair',
                    'ID': kp['KeyPairId'],
                    'Name': key_name,
                    'State': 'N/A', # Key pairs don't have a state
                    'Details': json.dumps(details),
                    'CreationDate': kp.get('CreateTime', {}).isoformat() if kp.get('CreateTime') else 'N/A'
                })
        except Exception as e:
            logger.error(f"Error listing EC2 Key Pairs in region {region}: {e}")
        return key_pairs_out

    def list_elastic_ips(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Elastic IPs in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        eips_out = []
        try:
            response = ec2_client.describe_addresses()
            for eip in response['Addresses']:
                tags_list = eip.get('Tags', [])
                eip_name = self._extract_name_from_tags(tags_list)
                
                details = {
                    "public_ip": eip['PublicIp'],
                    "private_ip": eip.get('PrivateIpAddress', 'N/A'),
                    "domain": eip['Domain'],
                    "instance_id": eip.get('InstanceId', 'N/A'),
                    "network_interface_id": eip.get('NetworkInterfaceId', 'N/A'),
                    "tags": self._get_tags_str_from_list(tags_list)
                }

                eips_out.append({
                    'Region': region,
                    'ResourceType': 'Elastic IP',
                    'ID': eip.get('AllocationId', eip['PublicIp']),
                    'Name': eip_name,
                    'State': 'associated' if eip.get('InstanceId') else 'unassociated',
                    'Details': json.dumps(details),
                    'CreationDate': 'N/A' # EIPs don't have a creation timestamp in this call
                })
        except Exception as e:
            logger.error(f"Error listing Elastic IPs in region {region}: {e}")
        return eips_out

    def list_security_groups(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Security Groups in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        sgs_out = []
        try:
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    if sg['GroupName'] == 'default':
                        continue # Skip default SGs
                    
                    tags_list = sg.get('Tags', [])
                    sg_name = sg.get('GroupName', 'N/A') # Use GroupName as Name

                    details = {
                        "description": sg['Description'],
                        "vpc_id": sg.get('VpcId', 'N/A'),
                        "owner_id": sg['OwnerId'],
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    sgs_out.append({
                        'Region': region,
                        'ResourceType': 'Security Group',
                        'ID': sg['GroupId'],
                        'Name': sg_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Security Groups in region {region}: {e}")
        return sgs_out

    def list_vpcs(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing VPCs in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        vpcs_out = []
        try:
            response = ec2_client.describe_vpcs()
            for vpc in response['Vpcs']:
                if vpc.get('IsDefault', False):
                    continue # Skip default VPCs
                    
                tags_list = vpc.get('Tags', [])
                vpc_name = self._extract_name_from_tags(tags_list)
                
                details = {
                    "cidr_block": vpc['CidrBlock'],
                    "instance_tenancy": vpc['InstanceTenancy'],
                    "dhcp_options_id": vpc['DhcpOptionsId'],
                    "tags": self._get_tags_str_from_list(tags_list)
                }

                vpcs_out.append({
                    'Region': region,
                    'ResourceType': 'VPC',
                    'ID': vpc['VpcId'],
                    'Name': vpc_name,
                    'State': vpc['State'],
                    'Details': json.dumps(details),
                    'CreationDate': 'N/A'
                })
        except Exception as e:
            logger.error(f"Error listing VPCs in region {region}: {e}")
        return vpcs_out
    
    def list_subnets(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Subnets in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        subnets_out = []
        try:
            paginator = ec2_client.get_paginator('describe_subnets')
            for page in paginator.paginate():
                for subnet in page['Subnets']:
                    if subnet.get('DefaultForAz', False):
                        continue # Skip default subnets
                        
                    tags_list = subnet.get('Tags', [])
                    subnet_name = self._extract_name_from_tags(tags_list)

                    details = {
                        "vpc_id": subnet['VpcId'],
                        "cidr_block": subnet['CidrBlock'],
                        "availability_zone": subnet['AvailabilityZone'],
                        "available_ip_count": subnet['AvailableIpAddressCount'],
                        "map_public_ip_on_launch": subnet['MapPublicIpOnLaunch'],
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    subnets_out.append({
                        'Region': region,
                        'ResourceType': 'Subnet',
                        'ID': subnet['SubnetId'],
                        'Name': subnet_name,
                        'State': subnet['State'],
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Subnets in region {region}: {e}")
        return subnets_out
    
    def list_route_tables(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Route Tables in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        route_tables_out = []
        try:
            paginator = ec2_client.get_paginator('describe_route_tables')
            for page in paginator.paginate():
                for rt in page['RouteTables']:
                    is_main_rt = any(assoc.get('Main', False) for assoc in rt.get('Associations', []))
                    if is_main_rt:
                        continue # Skip main route tables
                    
                    tags_list = rt.get('Tags', [])
                    rt_name = self._extract_name_from_tags(tags_list)
                    
                    routes_info = []
                    for route in rt.get('Routes', []):
                        target = route.get('GatewayId') or route.get('NatGatewayId') or \
                                 route.get('InstanceId') or route.get('NetworkInterfaceId') or 'N/A'
                        dest = route.get('DestinationCidrBlock') or route.get('DestinationPrefixListId') or 'N/A'
                        routes_info.append(f"{dest} -> {target}")

                    details = {
                        "vpc_id": rt['VpcId'],
                        "routes": "; ".join(routes_info),
                        "associations": ", ".join([assoc.get('SubnetId', 'N/A') for assoc in rt.get('Associations', []) if assoc.get('SubnetId')]),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    route_tables_out.append({
                        'Region': region,
                        'ResourceType': 'Route Table',
                        'ID': rt['RouteTableId'],
                        'Name': rt_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Route Tables in region {region}: {e}")
        return route_tables_out
    
    def list_internet_gateways(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Internet Gateways in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        igws_out = []
        
        default_vpc_id = None
        try:
            default_vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
            if default_vpcs.get('Vpcs'):
                default_vpc_id = default_vpcs['Vpcs'][0]['VpcId']
        except Exception as e:
            logger.warning(f"Could not check for default VPC in {region}: {e}")

        try:
            paginator = ec2_client.get_paginator('describe_internet_gateways')
            for page in paginator.paginate():
                for igw in page['InternetGateways']:
                    if default_vpc_id and any(attach['VpcId'] == default_vpc_id for attach in igw.get('Attachments', [])):
                        continue # Skip default IGW

                    tags_list = igw.get('Tags', [])
                    igw_name = self._extract_name_from_tags(tags_list)
                    
                    attachments = ", ".join([f"{attach['VpcId']} ({attach['State']})" for attach in igw.get('Attachments', [])])
                    details = {
                        "attachments": attachments,
                        "owner_id": igw.get('OwnerId', 'N/A'),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    igws_out.append({
                        'Region': region,
                        'ResourceType': 'Internet Gateway',
                        'ID': igw['InternetGatewayId'],
                        'Name': igw_name,
                        'State': attachments if attachments else 'detached',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Internet Gateways in region {region}: {e}")
        return igws_out
    
    def list_nat_gateways(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing NAT Gateways in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        nat_gws_out = []
        try:
            paginator = ec2_client.get_paginator('describe_nat_gateways')
            for page in paginator.paginate():
                for nat_gw in page['NatGateways']:
                    if nat_gw['State'] == 'deleted':
                        continue

                    tags_list = nat_gw.get('Tags', [])
                    nat_gw_name = self._extract_name_from_tags(tags_list)

                    addresses = ", ".join([addr.get('PublicIp', 'N/A') for addr in nat_gw.get('NatGatewayAddresses', [])])
                    details = {
                        "vpc_id": nat_gw['VpcId'],
                        "subnet_id": nat_gw['SubnetId'],
                        "public_ips": addresses,
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    nat_gws_out.append({
                        'Region': region,
                        'ResourceType': 'NAT Gateway',
                        'ID': nat_gw['NatGatewayId'],
                        'Name': nat_gw_name,
                        'State': nat_gw['State'],
                        'Details': json.dumps(details),
                        'CreationDate': nat_gw['CreateTime'].isoformat() if nat_gw.get('CreateTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing NAT Gateways in region {region}: {e}")
        return nat_gws_out
    
    def list_vpc_endpoints(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing VPC Endpoints in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        endpoints_out = []
        try:
            paginator = ec2_client.get_paginator('describe_vpc_endpoints')
            for page in paginator.paginate():
                for endpoint in page['VpcEndpoints']:
                    tags_list = endpoint.get('Tags', [])
                    endpoint_name = self._extract_name_from_tags(tags_list)

                    details = {
                        "vpc_id": endpoint['VpcId'],
                        "service_name": endpoint['ServiceName'],
                        "type": endpoint['VpcEndpointType'],
                        "subnet_ids": ", ".join(endpoint.get('SubnetIds', [])),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    endpoints_out.append({
                        'Region': region,
                        'ResourceType': 'VPC Endpoint',
                        'ID': endpoint['VpcEndpointId'],
                        'Name': endpoint_name,
                        'State': endpoint['State'],
                        'Details': json.dumps(details),
                        'CreationDate': endpoint['CreationTimestamp'].isoformat() if endpoint.get('CreationTimestamp') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing VPC Endpoints in region {region}: {e}")
        return endpoints_out
    
    def list_network_acls(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Network ACLs in region: {region}")
        ec2_client = boto3.client('ec2', region_name=region)
        acls_out = []
        try:
            paginator = ec2_client.get_paginator('describe_network_acls')
            for page in paginator.paginate():
                for acl in page['NetworkAcls']:
                    if acl.get('IsDefault', False):
                        continue # Skip default NACLs
                        
                    tags_list = acl.get('Tags', [])
                    acl_name = self._extract_name_from_tags(tags_list)

                    details = {
                        "vpc_id": acl['VpcId'],
                        "owner_id": acl['OwnerId'],
                        "associations": ", ".join([assoc.get('SubnetId', 'N/A') for assoc in acl.get('Associations', [])]),
                        "entries_count": len(acl.get('Entries', [])),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    acls_out.append({
                        'Region': region,
                        'ResourceType': 'Network ACL',
                        'ID': acl['NetworkAclId'],
                        'Name': acl_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Network ACLs in region {region}: {e}")
        return acls_out

    # --- S3 Service (Global, but processed regionally) ---

    def list_s3_buckets_global(self) -> List[Dict[str, Any]]:
        logger.info("Listing all S3 buckets (global)...")
        s3_client = boto3.client('s3', region_name='us-east-1')
        buckets_out = []
        try:
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                creation_date = bucket['CreationDate'].isoformat() if bucket['CreationDate'] else 'N/A'
                
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response['LocationConstraint'] or 'us-east-1'
                except Exception as e:
                    logger.error(f"Error getting location for S3 bucket {bucket_name}: {e}")
                    bucket_region = 'unknown'

                details = {
                    "location_constraint": bucket_region
                }

                buckets_out.append({
                    'Region': bucket_region, # Use bucket's actual region
                    'ResourceType': 'S3 Bucket',
                    'ID': bucket_name,
                    'Name': bucket_name, # S3 Buckets use their ID as their name
                    'State': 'N/A',
                    'Details': json.dumps(details),
                    'CreationDate': creation_date
                })
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {e}")
        return buckets_out

    # --- Lambda Service ---

    def list_lambda_functions(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Lambda functions in region: {region}")
        lambda_client = boto3.client('lambda', region_name=region)
        functions_out = []
        try:
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    func_name = function['FunctionName']
                    
                    details = {
                        "runtime": function['Runtime'],
                        "handler": function['Handler'],
                        "code_size_bytes": function['CodeSize'],
                        "timeout_sec": function['Timeout'],
                        "memory_mb": function['MemorySize'],
                        "description": function['Description'],
                        "role_arn": function['Role']
                    }

                    functions_out.append({
                        'Region': region,
                        'ResourceType': 'Lambda Function',
                        'ID': func_name,
                        'Name': func_name,
                        'State': function.get('State', 'N/A'),
                        'Details': json.dumps(details),
                        'CreationDate': function['LastModified'] # Use LastModified as best-effort date
                    })
        except Exception as e:
            logger.error(f"Error listing Lambda functions in region {region}: {e}")
        return functions_out

    # --- RDS Service ---

    def list_rds_instances(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing RDS instances in region: {region}")
        rds_client = boto3.client('rds', region_name=region)
        instances_out = []
        try:
            paginator = rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    tags_list = instance.get('TagList', [])
                    instance_name = instance['DBInstanceIdentifier'] # Use ID as name
                    
                    details = {
                        "engine": instance['Engine'],
                        "engine_version": instance['EngineVersion'],
                        "class": instance['DBInstanceClass'],
                        "storage_gb": instance['AllocatedStorage'],
                        "storage_type": instance['StorageType'],
                        "encrypted": instance['StorageEncrypted'],
                        "multi_az": instance['MultiAZ'],
                        "endpoint": instance['Endpoint']['Address'] if 'Endpoint' in instance else 'N/A',
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    instances_out.append({
                        'Region': region,
                        'ResourceType': 'RDS Instance',
                        'ID': instance['DBInstanceIdentifier'],
                        'Name': instance_name,
                        'State': instance['DBInstanceStatus'],
                        'Details': json.dumps(details),
                        'CreationDate': instance['InstanceCreateTime'].isoformat() if instance.get('InstanceCreateTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing RDS instances in region {region}: {e}")
        return instances_out
    
    def list_rds_snapshots(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing RDS Snapshots in region: {region}")
        rds_client = boto3.client('rds', region_name=region)
        snapshots_out = []
        try:
            paginator = rds_client.get_paginator('describe_db_snapshots')
            for page in paginator.paginate(IncludeShared=False, IncludePublic=False):
                for snap in page['DBSnapshots']:
                    tags_list = snap.get('TagList', [])
                    snap_name = snap['DBSnapshotIdentifier'] # Use ID as name

                    details = {
                        "db_instance": snap.get('DBInstanceIdentifier', 'N/A'),
                        "engine": snap['Engine'],
                        "storage_gb": snap['AllocatedStorage'],
                        "snapshot_type": snap['SnapshotType'],
                        "encrypted": snap['Encrypted'],
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    snapshots_out.append({
                        'Region': region,
                        'ResourceType': 'RDS Snapshot',
                        'ID': snap['DBSnapshotIdentifier'],
                        'Name': snap_name,
                        'State': snap['Status'],
                        'Details': json.dumps(details),
                        'CreationDate': snap.get('SnapshotCreateTime', {}).isoformat() if snap.get('SnapshotCreateTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing RDS Snapshots in region {region}: {e}")
        return snapshots_out

    # --- KMS Service ---

    def list_kms_keys(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing KMS keys in region: {region}")
        kms_client = boto3.client('kms', region_name=region)
        keys_out = []
        try:
            paginator = kms_client.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        key_detail = kms_client.describe_key(KeyId=key['KeyId'])
                        key_metadata = key_detail['KeyMetadata']
                        
                        if key_metadata.get('KeyManager') != 'CUSTOMER':
                            continue # Skip AWS-managed keys

                        tags_response = kms_client.list_resource_tags(KeyId=key['KeyId'])
                        tags_list = tags_response.get('Tags', [])
                        key_name_tag = self._extract_name_from_tags(tags_list)
                        
                        # Get alias as name if tag is missing
                        alias_name = 'N/A'
                        if key_name_tag == 'N/A':
                            try:
                                aliases_response = kms_client.list_aliases(KeyId=key['KeyId'], Limit=1)
                                if aliases_response.get('Aliases'):
                                    alias_name = aliases_response['Aliases'][0]['AliasName']
                            except Exception:
                                pass # Ignore errors trying to find alias
                        
                        key_name = key_name_tag if key_name_tag != 'N/A' else alias_name

                        details = {
                            "arn": key_metadata['Arn'],
                            "key_usage": key_metadata['KeyUsage'],
                            "key_spec": key_metadata.get('KeySpec', 'N/A'),
                            "origin": key_metadata.get('Origin', 'N/A'),
                            "description": key_metadata.get('Description', 'N/A'),
                            "tags": self._get_tags_str_from_list(tags_list)
                        }

                        keys_out.append({
                            'Region': region,
                            'ResourceType': 'KMS Key',
                            'ID': key_metadata['KeyId'],
                            'Name': key_name,
                            'State': key_metadata['KeyState'],
                            'Details': json.dumps(details),
                            'CreationDate': key_metadata['CreationDate'].isoformat() if key_metadata.get('CreationDate') else 'N/A'
                        })
                    except Exception as e:
                        logger.error(f"Error getting details for KMS key {key['KeyId']}: {e}")
        except Exception as e:
            logger.error(f"Error listing KMS keys in region {region}: {e}")
        return keys_out
    
    def list_kms_aliases(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing KMS aliases in region: {region}")
        kms_client = boto3.client('kms', region_name=region)
        aliases_out = []
        try:
            paginator = kms_client.get_paginator('list_aliases')
            for page in paginator.paginate():
                for alias in page['Aliases']:
                    if alias['AliasName'].startswith('alias/aws/'):
                        continue # Skip default AWS-managed aliases
                        
                    alias_name = alias['AliasName']
                    details = {
                        "target_key_id": alias.get('TargetKeyId', 'N/A'),
                        "arn": alias['AliasArn']
                    }

                    aliases_out.append({
                        'Region': region,
                        'ResourceType': 'KMS Alias',
                        'ID': alias['AliasArn'],
                        'Name': alias_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': alias.get('CreationDate', {}).isoformat() if alias.get('CreationDate') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing KMS aliases in region {region}: {e}")
        return aliases_out

    # --- ELB/ASG Services ---

    def list_load_balancers(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Load Balancers in region: {region}")
        elbv2_client = boto3.client('elbv2', region_name=region)
        elb_client = boto3.client('elb', region_name=region)
        load_balancers_out = []
        
        try:
            # v2 Load Balancers (ALB/NLB)
            paginator_v2 = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator_v2.paginate():
                for lb in page['LoadBalancers']:
                    tags_response = elbv2_client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
                    tags_list = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])
                    lb_name = lb['LoadBalancerName']

                    details = {
                        "type": lb['Type'],
                        "dns_name": lb['DNSName'],
                        "scheme": lb['Scheme'],
                        "vpc_id": lb.get('VpcId', 'N/A'),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    load_balancers_out.append({
                        'Region': region,
                        'ResourceType': f"Load Balancer ({lb['Type']})",
                        'ID': lb['LoadBalancerArn'],
                        'Name': lb_name,
                        'State': lb['State']['Code'],
                        'Details': json.dumps(details),
                        'CreationDate': lb['CreatedTime'].isoformat() if lb.get('CreatedTime') else 'N/A'
                    })
            
            # v1 Load Balancers (Classic)
            paginator_v1 = elb_client.get_paginator('describe_load_balancers')
            for page in paginator_v1.paginate():
                lb_names = [lb['LoadBalancerName'] for lb in page['LoadBalancerDescriptions']]
                if not lb_names: continue
                
                tags_response = elb_client.describe_tags(LoadBalancerNames=lb_names)
                tags_map = {tag_desc['LoadBalancerName']: tag_desc['Tags'] for tag_desc in tags_response.get('TagDescriptions', [])}

                for lb in page['LoadBalancerDescriptions']:
                    lb_name = lb['LoadBalancerName']
                    tags_list = tags_map.get(lb_name, [])
                    
                    details = {
                        "type": "classic",
                        "dns_name": lb['DNSName'],
                        "scheme": lb.get('Scheme', 'internet-facing'),
                        "vpc_id": lb.get('VPCId', 'N/A'),
                        "instances": ", ".join([inst['InstanceId'] for inst in lb.get('Instances', [])]),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }
                    
                    load_balancers_out.append({
                        'Region': region,
                        'ResourceType': 'Classic Load Balancer',
                        'ID': lb_name,
                        'Name': lb_name,
                        'State': 'N/A', # No simple state
                        'Details': json.dumps(details),
                        'CreationDate': lb['CreatedTime'].isoformat() if lb.get('CreatedTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Load Balancers in region {region}: {e}")
        return load_balancers_out
    
    def list_target_groups(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Target Groups in region: {region}")
        elbv2_client = boto3.client('elbv2', region_name=region)
        target_groups_out = []
        try:
            paginator = elbv2_client.get_paginator('describe_target_groups')
            for page in paginator.paginate():
                for tg in page['TargetGroups']:
                    tags_response = elbv2_client.describe_tags(ResourceArns=[tg['TargetGroupArn']])
                    tags_list = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])
                    tg_name = tg['TargetGroupName']

                    details = {
                        "protocol": tg.get('Protocol', 'N/A'),
                        "port": tg.get('Port', 'N/A'),
                        "vpc_id": tg.get('VpcId', 'N/A'),
                        "target_type": tg.get('TargetType', 'N/A'),
                        "load_balancers": ", ".join(tg.get('LoadBalancerArns', [])),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    target_groups_out.append({
                        'Region': region,
                        'ResourceType': 'Target Group',
                        'ID': tg['TargetGroupArn'],
                        'Name': tg_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Target Groups in region {region}: {e}")
        return target_groups_out
    
    def list_auto_scaling_groups(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing Auto Scaling Groups in region: {region}")
        asg_client = boto3.client('autoscaling', region_name=region)
        asgs_out = []
        try:
            paginator = asg_client.get_paginator('describe_auto_scaling_groups')
            for page in paginator.paginate():
                for asg in page['AutoScalingGroups']:
                    tags_list = asg.get('Tags', [])
                    asg_name = asg['AutoScalingGroupName']
                    
                    details = {
                        "min_size": asg['MinSize'],
                        "max_size": asg['MaxSize'],
                        "desired_capacity": asg['DesiredCapacity'],
                        "instance_count": len(asg.get('Instances', [])),
                        "launch_template": asg.get('LaunchTemplate', {}).get('LaunchTemplateName', 'N/A'),
                        "launch_config": asg.get('LaunchConfigurationName', 'N/A'),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    asgs_out.append({
                        'Region': region,
                        'ResourceType': 'Auto Scaling Group',
                        'ID': asg['AutoScalingGroupARN'],
                        'Name': asg_name,
                        'State': 'N/A', # No simple state
                        'Details': json.dumps(details),
                        'CreationDate': asg['CreatedTime'].isoformat() if asg.get('CreatedTime') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing Auto Scaling Groups in region {region}: {e}")
        return asgs_out

    # --- ECS Services ---
    
    def list_ecs_clusters(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing ECS Clusters in region: {region}")
        ecs_client = boto3.client('ecs', region_name=region)
        clusters_out = []
        try:
            paginator = ecs_client.get_paginator('list_clusters')
            for page in paginator.paginate():
                cluster_arns = page.get('clusterArns', [])
                if not cluster_arns: continue
                
                response = ecs_client.describe_clusters(clusters=cluster_arns, include=['TAGS'])
                for cluster in response.get('clusters', []):
                    tags_list = cluster.get('tags', [])
                    cluster_name = cluster['clusterName']

                    details = {
                        "running_tasks": cluster.get('runningTasksCount', 0),
                        "pending_tasks": cluster.get('pendingTasksCount', 0),
                        "active_services": cluster.get('activeServicesCount', 0),
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    clusters_out.append({
                        'Region': region,
                        'ResourceType': 'ECS Cluster',
                        'ID': cluster['clusterArn'],
                        'Name': cluster_name,
                        'State': cluster.get('status', 'N/A'),
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing ECS Clusters in region {region}: {e}")
        return clusters_out

    def list_ecs_task_definitions(self, region: str) -> List[Dict[str, Any]]:
        logger.info(f"Listing ECS Task Definitions in region: {region}")
        ecs_client = boto3.client('ecs', region_name=region)
        task_defs_out = []
        try:
            paginator = ecs_client.get_paginator('list_task_definitions')
            for page in paginator.paginate(status='ACTIVE'): 
                for arn in page.get('taskDefinitionArns', []):
                    family_revision = arn.split('/')[-1]
                    family = family_revision.split(':')[0]
                    
                    details = {
                        "family": family,
                        "revision": arn.split(':')[-1],
                        "full_arn": arn
                    }

                    task_defs_out.append({
                        'Region': region,
                        'ResourceType': 'ECS Task Definition',
                        'ID': arn,
                        'Name': family_revision,
                        'State': 'ACTIVE',
                        'Details': json.dumps(details),
                        'CreationDate': 'N/A' # Not available in list call
                    })
        except Exception as e:
            logger.error(f"Error listing ECS Task Definitions in region {region}: {e}")
        return task_defs_out

    def list_ecs_services(self, region: str) -> List[Dict[str, Any]]:
        """List ECS Services in the specified region"""
        logger.info(f"Listing ECS Services in region: {region}")
        ecs_client = boto3.client('ecs', region_name=region)
        services_out = []
        try:
            # 1. List all clusters
            cluster_arns_pages = ecs_client.get_paginator('list_clusters').paginate()
            all_cluster_arns = [arn for page in cluster_arns_pages for arn in page.get('clusterArns', [])]
            
            for cluster_arn in all_cluster_arns:
                # 2. List all services in each cluster
                paginator = ecs_client.get_paginator('list_services')
                for page in paginator.paginate(cluster=cluster_arn):
                    service_arns = page.get('serviceArns', [])
                    if not service_arns:
                        continue
                        
                    # 3. Describe services in batches (max 10 services per call)
                    for i in range(0, len(service_arns), 10):
                        batch = service_arns[i:i+10]
                        response = ecs_client.describe_services(cluster=cluster_arn, services=batch, include=['TAGS'])
                        
                        for service in response.get('services', []):
                            tags_list = service.get('tags', [])
                            service_name = service['serviceName']
                            
                            details = {
                                "cluster_arn": cluster_arn,
                                "task_definition": service.get('taskDefinition', 'N/A'),
                                "desired_count": service['desiredCount'],
                                "pending_count": service['pendingCount'],
                                "running_count": service['runningCount'],
                                "launch_type": service.get('launchType', 'N/A'),
                                "platform_version": service.get('platformVersion', 'N/A'),
                                "tags": self._get_tags_str_from_list(tags_list)
                            }
                            
                            services_out.append({
                                'Region': region,
                                'ResourceType': 'ECS Service',
                                'ID': service['serviceArn'],
                                'Name': service_name,
                                'State': service.get('status', 'N/A'),
                                'Details': json.dumps(details),
                                'CreationDate': service.get('createdAt', {}).isoformat() if service.get('createdAt') else 'N/A'
                            })
        except Exception as e:
            logger.error(f"Error listing ECS Services in region {region}: {e}")
        return services_out

    def list_ecs_tasks(self, region: str) -> List[Dict[str, Any]]:
        """List ECS Tasks (Running, Stopped, Pending) in the specified region"""
        logger.info(f"Listing ECS Tasks (Running/Stopped/Pending) in region: {region}")
        ecs_client = boto3.client('ecs', region_name=region)
        tasks_out = []
        
        # Define states to check (RUNNING and PENDING are usually for active, STOPPED gives history)
        desired_statuses = ['RUNNING', 'PENDING', 'STOPPED']
        
        try:
            # 1. List all clusters
            cluster_arns_pages = ecs_client.get_paginator('list_clusters').paginate()
            all_cluster_arns = [arn for page in cluster_arns_pages for arn in page.get('clusterArns', [])]
            
            for cluster_arn in all_cluster_arns:
                for status in desired_statuses:
                    # 2. List task ARNs in batches by desired status
                    paginator = ecs_client.get_paginator('list_tasks')
                    # List by service to avoid potential huge list for standalone tasks
                    for page in paginator.paginate(cluster=cluster_arn, desiredStatus=status):
                        task_arns = page.get('taskArns', [])
                        if not task_arns:
                            continue
                            
                        # 3. Describe tasks in batches (max 100 tasks per call)
                        for i in range(0, len(task_arns), 100):
                            batch = task_arns[i:i+100]
                            response = ecs_client.describe_tasks(cluster=cluster_arn, tasks=batch, include=['TAGS'])
                            
                            for task in response.get('tasks', []):
                                tags_list = task.get('tags', [])
                                task_id_short = task['taskArn'].split('/')[-1]
                                
                                details = {
                                    "cluster_arn": cluster_arn,
                                    "task_definition": task.get('taskDefinitionArn', 'N/A'),
                                    "last_status": task.get('lastStatus', 'N/A'),
                                    "launch_type": task.get('launchType', 'N/A'),
                                    "started_by": task.get('startedBy', 'N/A'),
                                    "stop_code": task.get('stopCode', 'N/A'),
                                    "tags": self._get_tags_str_from_list(tags_list)
                                }
                                
                                tasks_out.append({
                                    'Region': region,
                                    'ResourceType': 'ECS Task',
                                    'ID': task['taskArn'],
                                    'Name': task_id_short,
                                    'State': f"{task.get('desiredStatus', 'N/A')} ({task.get('lastStatus', 'N/A')})",
                                    'Details': json.dumps(details),
                                    'CreationDate': task.get('createdAt', {}).isoformat() if task.get('createdAt') else 'N/A'
                                })
        except Exception as e:
            logger.error(f"Error listing ECS Tasks in region {region}: {e}")
        return tasks_out

    # --- IAM Services (Global) ---

    def list_iam_users_global(self) -> List[Dict[str, Any]]:
        logger.info("Listing all IAM Users (global)...")
        iam_client = boto3.client('iam', region_name='us-east-1')
        users_out = []
        try:
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    tags_list = []
                    try:
                        tags_response = iam_client.list_user_tags(UserName=user['UserName'])
                        tags_list = tags_response.get('Tags', [])
                    except Exception:
                        pass # Ignore permission errors on tags
                    
                    user_name = user['UserName']
                    
                    details = {
                        "arn": user['Arn'],
                        "password_last_used": user.get('PasswordLastUsed', {}).isoformat() if user.get('PasswordLastUsed') else 'N/A',
                        "tags": self._get_tags_str_from_list(tags_list)
                    }

                    users_out.append({
                        'Region': 'global',
                        'ResourceType': 'IAM User',
                        'ID': user['UserId'],
                        'Name': user_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': user['CreateDate'].isoformat() if user.get('CreateDate') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing IAM Users: {e}")
        return users_out

    def list_iam_groups_global(self) -> List[Dict[str, Any]]:
        logger.info("Listing all IAM Groups (global)...")
        iam_client = boto3.client('iam', region_name='us-east-1')
        groups_out = []
        try:
            paginator = iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_name = group['GroupName']
                    details = {
                        "arn": group['Arn'],
                        "path": group['Path']
                    }

                    groups_out.append({
                        'Region': 'global',
                        'ResourceType': 'IAM Group',
                        'ID': group['GroupId'],
                        'Name': group_name,
                        'State': 'N/A',
                        'Details': json.dumps(details),
                        'CreationDate': group['CreateDate'].isoformat() if group.get('CreateDate') else 'N/A'
                    })
        except Exception as e:
            logger.error(f"Error listing IAM Groups: {e}")
        return groups_out

    # --- Main Orchestration ---

    def list_all_resources(self, regions: List[str], resource_types: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"Starting resource listing for regions: {regions}, resource types: {resource_types}")
        
        all_resources = []
        regional_resource_types = list(resource_types)
        
        # Mapping of REGIONAL resource types to their listing functions
        resource_list_functions = {
            'ec2_instances': self.list_ec2_instances,
            'ec2_volumes': self.list_ec2_volumes,
            'ec2_amis': self.list_ec2_amis,
            'ec2_snapshots': self.list_ec2_snapshots,
            'ec2_key_pairs': self.list_ec2_key_pairs,
            'lambda_functions': self.list_lambda_functions,
            'rds_instances': self.list_rds_instances,
            'rds_snapshots': self.list_rds_snapshots,
            'elastic_ips': self.list_elastic_ips,
            'security_groups': self.list_security_groups,
            'vpcs': self.list_vpcs,
            'subnets': self.list_subnets,
            'route_tables': self.list_route_tables,
            'internet_gateways': self.list_internet_gateways,
            'nat_gateways': self.list_nat_gateways,
            'vpc_endpoints': self.list_vpc_endpoints,
            'network_acls': self.list_network_acls,
            'kms_keys': self.list_kms_keys,
            'kms_aliases': self.list_kms_aliases,
            'load_balancers': self.list_load_balancers,
            'target_groups': self.list_target_groups,
            'auto_scaling_groups': self.list_auto_scaling_groups,
            'ecs_clusters': self.list_ecs_clusters,
            'ecs_task_definitions': self.list_ecs_task_definitions,
            'ecs_services': self.list_ecs_services,
            'ecs_tasks': self.list_ecs_tasks,
        }
        
        # Handle global services first
        global_service_funcs = {
            's3_buckets': self.list_s3_buckets_global,
            'iam_users': self.list_iam_users_global,
            'iam_groups': self.list_iam_groups_global,
        }

        # Filter regional types to only include those requested and regional functions
        regional_resource_types = [r for r in regional_resource_types if r in resource_list_functions]

        for service_name, list_func in global_service_funcs.items():
            if service_name in resource_types: # Check against original requested types
                logger.info(f"Processing global service: {service_name}")
                resources = list_func()
                
                if service_name == 's3_buckets':
                    # Special filter for S3 to only show buckets in requested regions
                    regions_set = set(regions)
                    for resource in resources:
                        # Only append if the bucket region is one of the target regions
                        if resource['Region'] in regions_set or 'global' in regions_set:
                            all_resources.append(resource)
                else:
                    all_resources.extend(resources)
            
        # Process regional services
        for region in regions:
            for resource_type in regional_resource_types:
                if resource_type in resource_list_functions:
                    list_func = resource_list_functions[resource_type]
                    try:
                        resources = list_func(region)
                        all_resources.extend(resources)
                    except Exception as e:
                        logger.error(f"Failed to list {resource_type} in {region}: {e}")
        
        return all_resources
    
    def export_to_csv(self, resources: List[Dict[str, Any]], filename: str):
        """Export resources to a simplified CSV file"""
        if not resources:
            logger.info("No resources to export")
            return
        
        # Hardcoded fieldnames as requested by user
        fieldnames = ['Region', 'ResourceType', 'ID', 'Name', 'State', 'Details', 'CreationDate']
        
        # Write to CSV file
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for resource in resources:
                    writer.writerow(resource)
            
            logger.info(f"Exported {len(resources)} resources to {filename}")
        except IOError as e:
            logger.error(f"Error writing to CSV file {filename}: {e}")


@click.command()
@click.option('--resource-types', '-r', multiple=True, 
              type=click.Choice(ALL_RESOURCE_TYPES), 
              help='Resource types to list (can be specified multiple times). If not specified, all resource types will be listed.')
@click.option('--regions', '-rg', multiple=True, 
              help='Specific regions to process (default: all regions)')
@click.option('--output', '-o', default='aws_resources_simplified.csv', 
              show_default=True,
              help='Output CSV filename')
@click.option('--include-all-regions', is_flag=True,
              help='Include resources from all regions (overrides --regions if specified)')
def main(resource_types, regions, output, include_all_regions):
    """
    AWS Resource Lister - List non-default AWS resources and export to a simplified CSV
    """
    lister = AWSResourceLister()
    
    if not resource_types:
        resource_types = tuple(ALL_RESOURCE_TYPES)
    
    if include_all_regions:
        regions_to_scan = lister.get_all_regions()
        click.echo(f"Scanning all regions: {len(regions_to_scan)} regions found")
    elif not regions:
        regions_to_scan = lister.get_all_regions()
        click.echo(f"Scanning all regions (default): {len(regions_to_scan)} regions found")
    else:
        regions_to_scan = list(regions)
        click.echo(f"Scanning specified regions: {regions_to_scan}")
    
    if not regions_to_scan:
        click.echo("No regions to scan. Exiting.")
        return

    click.echo(f"Resource types to scan: {list(resource_types)}")
    click.echo(f"Output file: {output}")
    
    resources = lister.list_all_resources(regions_to_scan, list(resource_types))
    
    lister.export_to_csv(resources, output)
    
    click.echo(f"Resource listing complete. Exported {len(resources)} resources to {output}")


if __name__ == "__main__":
    main()