#!/usr/bin/env python3
"""
Main entry point for cloud resource management tools.
Supports both AWS and GCP resource listing and management.
"""

import argparse
import sys
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description='Cloud Resource Management Tools',
        epilog='''
Examples:
  python main.py gcp list --project my-project
  python main.py gcp list --project my-project --instances-only
  python main.py aws list --resource-types ec2_instances s3_buckets --regions us-east-1 eu-west-1
  python main.py aws list --include-all-regions
        '''
    )
    subparsers = parser.add_subparsers(dest='service', help='Cloud service to manage')
    
    # GCP subparser
    gcp_parser = subparsers.add_parser('gcp', help='Google Cloud Platform tools')
    gcp_subparsers = gcp_parser.add_subparsers(dest='command', help='GCP command to run')
    
    # GCP list command
    gcp_list_parser = gcp_subparsers.add_parser('list', help='List GCP resources')
    gcp_list_parser.add_argument('--project', type=str, required=True, 
                                help='GCP Project ID')
    gcp_list_parser.add_argument('--instances-only', action='store_true',
                                help='List only instances')
    gcp_list_parser.add_argument('--vpcs-only', action='store_true',
                                help='List only VPC networks')
    gcp_list_parser.add_argument('--ips-only', action='store_true',
                                help='List only reserved IPs')
    gcp_list_parser.add_argument('--snapshots-only', action='store_true',
                                help='List only snapshots')
    gcp_list_parser.add_argument('--disks-only', action='store_true',
                                help='List only disks')
    gcp_list_parser.add_argument('--storage-only', action='store_true',
                                help='List only storage buckets')
    gcp_list_parser.add_argument('--cloudrun-only', action='store_true',
                                help='List only Cloud Run services')
    
    # AWS subparser
    aws_parser = subparsers.add_parser('aws', help='Amazon Web Services tools')
    aws_subparsers = aws_parser.add_subparsers(dest='command', help='AWS command to run')
    
    # AWS list command
    aws_list_parser = aws_subparsers.add_parser('list', help='List AWS resources')
    aws_list_parser.add_argument('--resource-types', '-r', nargs='+', 
                                choices=['ec2_instances', 'ec2_volumes', 'ec2_snapshots', 
                                        's3_buckets', 'lambda_functions', 'rds_instances',
                                        'ecs_clusters', 'security_groups', 'vpcs'],
                                help='Resource types to list')
    aws_list_parser.add_argument('--regions', '-rg', nargs='+',
                                help='Specific regions to process')
    aws_list_parser.add_argument('--include-all-regions', action='store_true',
                                help='Include resources from all regions')
    aws_list_parser.add_argument('--output', '-o', default='aws_resources.csv',
                                help='Output CSV filename')
    
    args = parser.parse_args()
    
    if not args.service:
        parser.print_help()
        return 1
    
    if args.service == 'gcp':
        return run_gcp_command(args)
    elif args.service == 'aws':
        return run_aws_command(args)
    else:
        print(f"Unknown service: {args.service}")
        return 1


def run_gcp_command(args):
    """Run GCP commands"""
    if args.command != 'list':
        print(f"Command '{args.command}' not implemented for GCP")
        return 1
    
    # Add the gcp_resources directory to the path
    gcp_resources_path = os.path.join(os.path.dirname(__file__), 'gcp_resources')
    sys.path.insert(0, gcp_resources_path)
    
    try:
        from gcp_resource_lister import main as gcp_lister_main
        
        # Prepare arguments for the GCP lister
        original_argv = sys.argv
        sys.argv = ['gcp_resource_lister.py', '--project', args.project]
        
        if args.instances_only:
            sys.argv.append('--instances-only')
        if args.vpcs_only:
            sys.argv.append('--vpcs-only')
        if args.ips_only:
            sys.argv.append('--ips-only')
        if args.snapshots_only:
            sys.argv.append('--snapshots-only')
        if args.disks_only:
            sys.argv.append('--disks-only')
        if args.storage_only:
            sys.argv.append('--storage-only')
        if args.cloudrun_only:
            sys.argv.append('--cloudrun-only')
        
        try:
            return gcp_lister_main()
        finally:
            sys.argv = original_argv
            
    except ImportError as e:
        print(f"Error importing GCP module: {e}")
        return 1
    except Exception as e:
        print(f"Error running GCP command: {e}")
        return 1


def run_aws_command(args):
    """Run AWS commands"""
    if args.command != 'list':
        print(f"Command '{args.command}' not implemented for AWS")
        return 1
    
    # Add the aws-resource directory to the path
    aws_resource_path = os.path.join(os.path.dirname(__file__), 'aws-resource')
    sys.path.insert(0, aws_resource_path)
    
    try:
        from aws_resource_lister import main as aws_lister_main
        
        # Prepare arguments for the AWS lister using the original argparse interface
        original_argv = sys.argv
        sys.argv = ['aws_resource_lister.py']
        
        if args.resource_types:
            # Map resource types to script flags
            resource_type_mapping = {
                'ec2_instances': '--instances-only',
                'ec2_volumes': '--volumes-only', 
                's3_buckets': '--s3-only',
                'rds_instances': '--rds-only',
                'lambda_functions': '--lambda-only',
                'security_groups': '--security-groups-only',
                'vpcs': '--vpcs-only'
            }
            
            for resource_type in args.resource_types:
                if resource_type in resource_type_mapping:
                    sys.argv.append(resource_type_mapping[resource_type])
        
        # Note: The current AWS script doesn't support --regions, --include-all-regions, --output
        # It has its own separate argument structure
        
        try:
            return aws_lister_main()
        finally:
            sys.argv = original_argv
        
    except ImportError as e:
        print(f"Error importing AWS module: {e}")
        return 1
    except Exception as e:
        print(f"Error running AWS command: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code if exit_code is not None else 0)
