import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description='Cloud Resource Management Tools')
    parser.add_argument('service', choices=['aws', 'gcp'], help='Cloud service to manage')
    parser.add_argument('command', help='Command to run')
    parser.add_argument('--project', type=str, help='Project ID (for GCP)')
    parser.add_argument('--region', type=str, help='Region (for AWS)')
    
    args = parser.parse_args()
    
    if args.service == 'gcp':
        # Add the gcp_resources directory to the path
        gcp_resources_path = os.path.join(os.path.dirname(__file__), 'gcp_resources')
        sys.path.insert(0, gcp_resources_path)
        
        if args.command == 'list':
            # Import and run the GCP lister
            from gcp_resource_lister import main as gcp_lister_main
            # Prepare arguments for the GCP lister
            original_argv = sys.argv
            sys.argv = ['gcp_resource_lister.py']
            if args.project:
                sys.argv.extend(['--project', args.project])
            try:
                return gcp_lister_main()
            finally:
                sys.argv = original_argv
        else:
            print(f"Command '{args.command}' not implemented for GCP")
            return 1
    elif args.service == 'aws':
        print("AWS commands are not yet implemented in this version")
        return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code if exit_code is not None else 0)
