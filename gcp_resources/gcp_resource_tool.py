#!/usr/bin/env python3
"""
Main entry point for GCP resource management tools.
"""

import sys
import argparse
import os

# Add the current directory to the path so we can import from the same package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gcp_resource_lister import main as gcp_lister_main

def main():
    parser = argparse.ArgumentParser(description='GCP Resource Management Tools')
    parser.add_argument('command', choices=['list'], help='Available commands')
    parser.add_argument('--project', type=str, help='GCP Project ID')
    parser.add_argument('--instances-only', action='store_true', help='List only instances')
    parser.add_argument('--vpcs-only', action='store_true', help='List only VPC networks')
    parser.add_argument('--ips-only', action='store_true', help='List only reserved IPs')
    parser.add_argument('--snapshots-only', action='store_true', help='List only snapshots with their labels')
    parser.add_argument('--disks-only', action='store_true', help='List only disks with their labels')
    
    args = parser.parse_args()
    
    if args.command == 'list':
        # Create a mock sys.argv for the gcp_resource_lister
        lister_args = ['gcp_resource_lister.py']
        if args.project:
            lister_args.extend(['--project', args.project])
        if args.instances_only:
            lister_args.append('--instances-only')
        if args.vpcs_only:
            lister_args.append('--vpcs-only')
        if args.ips_only:
            lister_args.append('--ips-only')
        if args.snapshots_only:
            lister_args.append('--snapshots-only')
        if args.disks_only:
            lister_args.append('--disks-only')
        
        # Temporarily replace sys.argv for the function call
        original_argv = sys.argv
        sys.argv = lister_args
        
        try:
            result = gcp_lister_main()
            return result
        finally:
            sys.argv = original_argv

if __name__ == "__main__":
    sys.exit(main())