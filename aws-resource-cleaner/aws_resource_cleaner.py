#!/usr/bin/env python3
"""
AWS Resource Cleaner - Delete AWS resources region by region with preservation rules
"""
import boto3
import json
import click
from typing import Dict, List, Set
import logging
import sys

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AWSResourceCleaner:
    """
    A class to clean AWS resources region by region with configurable preservation rules
    """
    
    def __init__(self, config_file: str = "config.json", skip_defaults: bool = True):
        self.config_file = config_file
        self.config = self.load_config()
        self.excluded_resources = self.config.get("excluded_resources", {})
        self.skip_defaults = skip_defaults
        
    def load_config(self) -> Dict:
        """Load configuration from a file"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Configuration file {self.config_file} not found. Using default settings.")
            return {"excluded_resources": {}}
    
    def get_all_regions(self) -> List[str]:
        """Get all available AWS regions"""
        ec2_client = boto3.client('ec2', region_name='us-east-1')  # Use us-east-1 to list regions
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    
    def get_resources_to_preserve(self, region: str, resource_type: str) -> Set[str]:
        """Get a set of resource IDs that should be preserved in a specific region"""
        region_preserved = self.excluded_resources.get(region, {}).get(resource_type, [])
        all_regions_preserved = self.excluded_resources.get("all_regions", {}).get(resource_type, [])
        return set(region_preserved + all_regions_preserved)
    
    def ask_confirmation(self, resource_type: str, resource_id: str, region: str) -> bool:
        """Ask for confirmation before deleting a resource"""
        while True:
            response = input(f"Delete {resource_type} {resource_id} in {region}? (y/n): ").lower().strip()
            if response == 'y':
                return True
            if response == 'n':
                logger.info(f"Skipping {resource_type} {resource_id}...")
                return False
            print("Please enter 'y' or 'n'.")
    
    def delete_ec2_instances(self, region: str):
        """Delete EC2 instances in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing EC2 instances in region: {region}")
        
        preserved_instances = self.get_resources_to_preserve(region, "ec2_instances")
        if preserved_instances:
            logger.info(f"Preserving EC2 instances: {preserved_instances}")
        
        ec2_resource = boto3.resource('ec2', region_name=region)
        
        try:
            instances = ec2_resource.instances.all()
            for instance in instances:
                if instance.id not in preserved_instances:
                    if instance.state['Name'] not in ['terminated', 'terminating']:
                        if self.ask_confirmation("EC2 Instance", instance.id, region):
                            logger.info(f"Terminating EC2 instance: {instance.id}")
                            try:
                                instance.terminate()
                            except Exception as e:
                                logger.error(f"Error terminating instance {instance.id}: {e}")
                else:
                    logger.info(f"Skipping preserved EC2 instance: {instance.id}")
        except Exception as e:
            logger.error(f"Error processing EC2 instances in region {region}: {e}")
    
    def delete_ec2_volumes(self, region: str):
        """Delete EC2 volumes in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing EC2 volumes in region: {region}")
        
        preserved_volumes = self.get_resources_to_preserve(region, "ec2_volumes")
        if preserved_volumes:
            logger.info(f"Preserving EC2 volumes: {preserved_volumes}")
        
        ec2_resource = boto3.resource('ec2', region_name=region)
        
        try:
            volumes = ec2_resource.volumes.all()
            for volume in volumes:
                if volume.id not in preserved_volumes:
                    if volume.state == 'available':
                        if self.ask_confirmation("EC2 Volume", volume.id, region):
                            logger.info(f"Deleting EC2 volume: {volume.id}")
                            try:
                                volume.delete()
                            except Exception as e:
                                logger.error(f"Error deleting volume {volume.id}: {e}")
                else:
                    logger.info(f"Skipping preserved EC2 volume: {volume.id}")
        except Exception as e:
            logger.error(f"Error processing EC2 volumes in region {region}: {e}")
    
    def delete_ec2_snapshots(self, region: str):
        """Delete EC2 snapshots in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing EC2 snapshots in region: {region}")
        
        preserved_snapshots = self.get_resources_to_preserve(region, "ec2_snapshots")
        if preserved_snapshots:
            logger.info(f"Preserving EC2 snapshots: {preserved_snapshots}")
        
        ec2_client = boto3.client('ec2', region_name=region)
        
        try:
            snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])['Snapshots']
            for snapshot in snapshots:
                snapshot_id = snapshot['SnapshotId']
                if snapshot_id not in preserved_snapshots:
                    if self.ask_confirmation("EC2 Snapshot", snapshot_id, region):
                        logger.info(f"Deleting EC2 snapshot: {snapshot_id}")
                        try:
                            ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                        except Exception as e:
                            logger.error(f"Error deleting snapshot {snapshot_id}: {e}")
                else:
                    logger.info(f"Skipping preserved EC2 snapshot: {snapshot_id}")
        except Exception as e:
            logger.error(f"Error processing EC2 snapshots in region {region}: {e}")
    
    def delete_s3_buckets(self, region: str):
        """Delete S3 buckets in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing S3 buckets in region: {region}")
        
        preserved_buckets = self.get_resources_to_preserve(region, "s3_buckets")
        if preserved_buckets:
            logger.info(f"Preserving S3 buckets: {preserved_buckets}")
        
        s3_client = boto3.client('s3', region_name=region)
        
        try:
            buckets = s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                if bucket_name not in preserved_buckets:
                    if self.ask_confirmation("S3 Bucket", bucket_name, region):
                        logger.info(f"Deleting S3 bucket: {bucket_name}")
                        try:
                            # First, delete all objects in the bucket
                            s3_resource = boto3.resource('s3', region_name=region)
                            bucket_resource = s3_resource.Bucket(bucket_name)
                            
                            # Delete all objects
                            bucket_resource.objects.all().delete()
                            
                            # Delete all object versions (if versioning is enabled)
                            bucket_resource.object_versions.all().delete()
                            
                            # Finally, delete the bucket
                            s3_client.delete_bucket(Bucket=bucket_name)
                        except Exception as e:
                            logger.error(f"Error deleting S3 bucket {bucket_name}: {e}")
                else:
                    logger.info(f"Skipping preserved S3 bucket: {bucket_name}")
        except Exception as e:
            logger.error(f"Error processing S3 buckets in region {region}: {e}")
    
    def delete_lambda_functions(self, region: str):
        """Delete Lambda functions in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing Lambda functions in region: {region}")
        
        preserved_functions = self.get_resources_to_preserve(region, "lambda_functions")
        if preserved_functions:
            logger.info(f"Preserving Lambda functions: {preserved_functions}")
        
        lambda_client = boto3.client('lambda', region_name=region)
        
        try:
            response = lambda_client.list_functions()
            for function in response['Functions']:
                function_name = function['FunctionName']
                if function_name not in preserved_functions:
                    if self.ask_confirmation("Lambda Function", function_name, region):
                        logger.info(f"Deleting Lambda function: {function_name}")
                        try:
                            lambda_client.delete_function(FunctionName=function_name)
                        except Exception as e:
                            logger.error(f"Error deleting Lambda function {function_name}: {e}")
                else:
                    logger.info(f"Skipping preserved Lambda function: {function_name}")
        except Exception as e:
            logger.error(f"Error processing Lambda functions in region {region}: {e}")
    
    def delete_rds_instances(self, region: str):
        """Delete RDS instances in the specified region, preserving those in the exclude list"""
        logger.info(f"Processing RDS instances in region: {region}")
        
        preserved_instances = self.get_resources_to_preserve(region, "rds_instances")
        if preserved_instances:
            logger.info(f"Preserving RDS instances: {preserved_instances}")
        
        rds_client = boto3.client('rds', region_name=region)
        
        try:
            response = rds_client.describe_db_instances()
            for instance in response['DBInstances']:
                instance_id = instance['DBInstanceIdentifier']
                if instance_id not in preserved_instances:
                    if self.ask_confirmation("RDS Instance", instance_id, region):
                        logger.info(f"Deleting RDS instance: {instance_id}")
                        try:
                            # Skip deletion if it's a cluster member
                            if 'DBClusterIdentifier' in instance:
                                logger.info(f"Skipping {instance_id} as it's part of a cluster")
                                continue
                            # Delete without final snapshot since this is a cleanup operation
                            rds_client.delete_db_instance(
                                DBInstanceIdentifier=instance_id,
                                SkipFinalSnapshot=True
                            )
                        except Exception as e:
                            logger.error(f"Error deleting RDS instance {instance_id}: {e}")
                else:
                    logger.info(f"Skipping preserved RDS instance: {instance_id}")
        except Exception as e:
            logger.error(f"Error processing RDS instances in region {region}: {e}")
    
    def delete_ecs_clusters(self, region: str):
        """Delete ECS clusters and services in the specified region"""
        logger.info(f"Processing ECS in region: {region}")
        
        ecs_client = boto3.client('ecs', region_name=region)
        
        try:
            clusters = ecs_client.list_clusters()['clusterArns']
            for cluster_arn in clusters:
                services = ecs_client.list_services(cluster=cluster_arn)['serviceArns']
                for service_arn in services:
                    if self.ask_confirmation("ECS Service", service_arn, region):
                        try:
                            ecs_client.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
                            ecs_client.delete_service(cluster=cluster_arn, service=service_arn, force=True)
                        except Exception as e:
                            logger.error(f"Error deleting ECS service {service_arn}: {e}")
                if self.ask_confirmation("ECS Cluster", cluster_arn, region):
                    try:
                        ecs_client.delete_cluster(cluster=cluster_arn)
                    except Exception as e:
                        logger.error(f"Error deleting ECS cluster {cluster_arn}: {e}")
        except Exception as e:
            logger.error(f"Error processing ECS in region {region}: {e}")
    
    def delete_elb(self, region: str):
        """Delete Load Balancers in the specified region"""
        logger.info(f"Processing ELB in region: {region}")
        
        elbv2_client = boto3.client('elbv2', region_name=region)
        elbv1_client = boto3.client('elb', region_name=region)
        
        try:
            for lb in elbv2_client.describe_load_balancers()['LoadBalancers']:
                if self.ask_confirmation("ELBv2", lb['LoadBalancerArn'], region):
                    try:
                        elbv2_client.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])
                    except Exception as e:
                        logger.error(f"Error deleting ELBv2 {lb['LoadBalancerArn']}: {e}")
            for lb in elbv1_client.describe_load_balancers()['LoadBalancerDescriptions']:
                if self.ask_confirmation("ELBv1", lb['LoadBalancerName'], region):
                    try:
                        elbv1_client.delete_load_balancer(LoadBalancerName=lb['LoadBalancerName'])
                    except Exception as e:
                        logger.error(f"Error deleting ELBv1 {lb['LoadBalancerName']}: {e}")
        except Exception as e:
            logger.error(f"Error processing ELB in region {region}: {e}")
    
    def delete_nat_gateways(self, region: str):
        """Delete NAT Gateways in the specified region"""
        logger.info(f"Processing NAT Gateways in region: {region}")
        
        ec2_client = boto3.client('ec2', region_name=region)
        
        try:
            nats = ec2_client.describe_nat_gateways(Filters=[{'Name': 'state', 'Values': ['available', 'pending']}])['NatGateways']
            for nat in nats:
                if self.ask_confirmation("NAT Gateway", nat['NatGatewayId'], region):
                    try:
                        ec2_client.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                    except Exception as e:
                        logger.error(f"Error deleting NAT Gateway {nat['NatGatewayId']}: {e}")
        except Exception as e:
            logger.error(f"Error processing NAT Gateways in region {region}: {e}")
    
    def delete_eips(self, region: str):
        """Delete Elastic IPs in the specified region"""
        logger.info(f"Processing EIPs in region: {region}")
        
        ec2_client = boto3.client('ec2', region_name=region)
        
        try:
            eips = ec2_client.describe_addresses()['Addresses']
            for eip in eips:
                if 'AssociationId' not in eip:
                    if self.ask_confirmation("Elastic IP", eip['PublicIp'], region):
                        try:
                            ec2_client.release_address(AllocationId=eip['AllocationId'])
                        except Exception as e:
                            logger.error(f"Error releasing EIP {eip['PublicIp']}: {e}")
        except Exception as e:
            logger.error(f"Error processing EIPs in region {region}: {e}")
    
    def delete_security_groups(self, region: str):
        """Delete Security Groups in the specified region, skipping default"""
        logger.info(f"Processing Security Groups in region: {region}")
        
        ec2_resource = boto3.resource('ec2', region_name=region)
        
        try:
            for sg in ec2_resource.security_groups.all():
                if self.skip_defaults and sg.group_name == 'default':
                    continue
                if self.ask_confirmation("Security Group", f"{sg.id} ({sg.group_name})", region):
                    try:
                        sg.delete()
                    except Exception as e:
                        logger.error(f"Error deleting Security Group {sg.id}: {e}")
        except Exception as e:
            logger.error(f"Error processing Security Groups in region {region}: {e}")
    
    def delete_vpcs(self, region: str):
        """Delete VPCs in the specified region, skipping default and handling dependencies"""
        logger.info(f"Processing VPCs in region: {region}")
        
        ec2_resource = boto3.resource('ec2', region_name=region)
        ec2_client = boto3.client('ec2', region_name=region)
        
        try:
            for vpc in ec2_resource.vpcs.all():
                if self.skip_defaults and vpc.is_default:
                    continue
                # Clean dependencies first
                self.clean_vpc_dependencies(ec2_client, vpc.id, region)
                if self.ask_confirmation("VPC", vpc.id, region):
                    try:
                        vpc.delete()
                    except Exception as e:
                        logger.error(f"Error deleting VPC {vpc.id}: {e}")
        except Exception as e:
            logger.error(f"Error processing VPCs in region {region}: {e}")
    
    def clean_vpc_dependencies(self, client, vpc_id: str, region: str):
        """Clean VPC dependencies"""
        # Delete subnets
        subnets = client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        for subnet in subnets:
            if self.skip_defaults and subnet.get('DefaultForAz'):
                continue
            if self.ask_confirmation("Subnet", subnet['SubnetId'], region):
                try:
                    client.delete_subnet(SubnetId=subnet['SubnetId'])
                except Exception as e:
                    logger.error(f"Error deleting Subnet {subnet['SubnetId']}: {e}")
        
        # Delete IGWs
        igws = client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])['InternetGateways']
        for igw in igws:
            if self.ask_confirmation("Internet Gateway", igw['InternetGatewayId'], region):
                try:
                    client.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
                    client.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                except Exception as e:
                    logger.error(f"Error deleting IGW {igw['InternetGatewayId']}: {e}")
        
        # Delete route tables
        rts = client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
        for rt in rts:
            if any(assoc.get('Main') for assoc in rt.get('Associations', [])):
                continue
            if self.ask_confirmation("Route Table", rt['RouteTableId'], region):
                try:
                    for assoc in rt.get('Associations', []):
                        if not assoc.get('Main'):
                            client.disassociate_route_table(AssociationId=assoc['RouteTableAssociationId'])
                    client.delete_route_table(RouteTableId=rt['RouteTableId'])
                except Exception as e:
                    logger.error(f"Error deleting Route Table {rt['RouteTableId']}: {e}")
        
        # Delete NACLs
        acls = client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NetworkAcls']
        for acl in acls:
            if acl.get('IsDefault'):
                continue
            if self.ask_confirmation("Network ACL", acl['NetworkAclId'], region):
                try:
                    client.delete_network_acl(NetworkAclId=acl['NetworkAclId'])
                except Exception as e:
                    logger.error(f"Error deleting NACL {acl['NetworkAclId']}: {e}")
    
    def delete_kms_keys(self, region: str):
        """Delete KMS keys in the specified region"""
        logger.info(f"Processing KMS in region: {region}")
        
        kms_client = boto3.client('kms', region_name=region)
        
        try:
            keys = kms_client.list_keys()['Keys']
            for key in keys:
                try:
                    desc = kms_client.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                    if desc['KeyManager'] == 'CUSTOMER' and desc['KeyState'] == 'Enabled':
                        if self.ask_confirmation("KMS Key", key['KeyId'], region):
                            try:
                                kms_client.schedule_key_deletion(KeyId=key['KeyId'], PendingWindowInDays=7)
                            except Exception as e:
                                logger.error(f"Error scheduling KMS key deletion {key['KeyId']}: {e}")
                except Exception as e:
                    logger.error(f"Error describing KMS key {key['KeyId']}: {e}")
        except Exception as e:
            logger.error(f"Error processing KMS in region {region}: {e}")
    
    def clean_region(self, region: str, resource_types: List[str]):
        """Clean specific resource types in a region"""
        logger.info(f"Starting cleanup for region: {region}")
        
        # Map resource types to their deletion functions
        resource_deletion_functions = {
            'ec2_instances': self.delete_ec2_instances,
            'ec2_volumes': self.delete_ec2_volumes,
            'ec2_snapshots': self.delete_ec2_snapshots,
            's3_buckets': self.delete_s3_buckets,
            'lambda_functions': self.delete_lambda_functions,
            'rds_instances': self.delete_rds_instances,
            'ecs_clusters': self.delete_ecs_clusters,
            'elb': self.delete_elb,
            'nat_gateways': self.delete_nat_gateways,
            'eips': self.delete_eips,
            'security_groups': self.delete_security_groups,
            'vpcs': self.delete_vpcs,
            'kms_keys': self.delete_kms_keys,
        }
        
        for resource_type in resource_types:
            if resource_type in resource_deletion_functions:
                deletion_func = resource_deletion_functions[resource_type]
                deletion_func(region)
            else:
                logger.warning(f"Resource type {resource_type} not supported")
    
    def clean_all_regions(self, resource_types: List[str], regions: List[str] = None):
        """Clean resources in all regions or specified regions"""
        if regions is None:
            regions = self.get_all_regions()
        
        logger.info(f"Starting cleanup for regions: {regions}")
        
        for region in regions:
            self.clean_region(region, resource_types)


@click.command()
@click.option('--resource-types', '-r', multiple=True, 
              type=click.Choice([
                  'ec2_instances', 'ec2_volumes', 'ec2_snapshots', 
                  's3_buckets', 'lambda_functions', 'rds_instances',
                  'ecs_clusters', 'elb', 'nat_gateways', 'eips',
                  'security_groups', 'vpcs', 'kms_keys'
              ]), 
              help='Resource types to delete (can be specified multiple times). If not specified, all resource types will be deleted.')
@click.option('--regions', '-rg', multiple=True, 
              help='Specific regions to process (default: all regions)')
@click.option('--config', '-c', default='config.json', 
              help='Configuration file path')
@click.option('--dry-run', is_flag=True, 
              help='Show what would be deleted without actually deleting')
@click.option('--skip-defaults/--no-skip-defaults', default=True,
              help='Skip default resources (default: True)')
def main(resource_types, regions, config, dry_run, skip_defaults):
    """
    AWS Resource Cleaner - Delete AWS resources region by region with preservation rules
    """
    # Default to all resource types if none specified
    if not resource_types:
        resource_types = ('ec2_instances', 'ec2_volumes', 'ec2_snapshots', 
                          's3_buckets', 'lambda_functions', 'rds_instances',
                          'ecs_clusters', 'elb', 'nat_gateways', 'eips',
                          'security_groups', 'vpcs', 'kms_keys')
    
    if dry_run:
        logger.info("Running in DRY RUN mode - no resources will be deleted")
    
    cleaner = AWSResourceCleaner(config_file=config, skip_defaults=skip_defaults)
    
    # If no regions specified, use all regions
    regions_list = list(regions) if regions else None
    
    # Enhanced safety checks
    click.echo("AWS Resource Cleaner")
    click.echo(f"Regions to process: {regions_list or 'all regions'}")
    click.echo(f"Resource types to delete: {list(resource_types)}")
    click.echo(f"Configuration file: {config}")
    click.echo(f"Skip defaults: {skip_defaults}")
    
    if dry_run:
        logger.info("DRY RUN: Would process regions and resource types as specified")
        logger.info(f"Regions: {regions_list or 'all regions'}")
        logger.info(f"Resource types: {list(resource_types)}")
        logger.info("No resources will be deleted in dry-run mode")
    else:
        click.confirm("This will delete resources as specified. Do you want to continue?", abort=True)
        click.echo("Starting the resource deletion process...")
        cleaner.clean_all_regions(resource_types, regions_list)
        click.echo("Resource deletion process completed.")


if __name__ == "__main__":
    main()