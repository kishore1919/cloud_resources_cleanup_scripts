# Scripts

This repository contains various utility scripts for cloud resource management for both AWS and Google Cloud Platform (GCP).

## Features

- **Unified Interface**: Single entry point (`main.py`) for both AWS and GCP
- **Comprehensive Resource Listing**: Supports major resource types across both platforms
- **CSV Export**: All resources exported to structured CSV files
- **Multi-Region Support**: Automatic region discovery and resource listing
- **Credential Management**: Supports various authentication methods for both platforms
- **Individual Script Access**: Direct execution of scripts without main interface

## Available Scripts

- `main.py` - Main entry point for cloud resource management tools (supports both AWS and GCP)
- `gcp_resources/` - Directory containing GCP resource management tools
  - `gcp_resource_lister.py` - Lists GCP resources (instances, VPCs, reserved IPs, disks, snapshots, storage buckets, Cloud Run services)
- `aws-resource/` - Directory containing AWS resource management tools
  - `aws_resource_lister.py` - Lists AWS resources and exports to CSV (EC2 instances, VPCs, S3 buckets, RDS instances, Lambda functions, etc.)

## Project Structure

```
scripts/
├── main.py                     # Unified CLI interface
├── requirements.txt           # Python dependencies
├── pyproject.toml            # Project configuration
├── .gitignore               # Git ignore rules
├── gcp_resources/
│   └── gcp_resource_lister.py # GCP resource lister
└── aws-resource/
    └── aws_resource_lister.py  # AWS resource lister
```

## Quick Start

Use the unified `main.py` interface for both cloud providers:

```bash
# GCP examples
python main.py gcp list --project my-project-id
python main.py gcp list --project my-project-id --instances-only

# AWS examples  
python main.py aws list
python main.py aws list --resource-types ec2_instances s3_buckets
```

## Direct Script Usage

You can also run the scripts directly without using `main.py`:

```bash
# Run GCP script directly
python gcp_resources/gcp_resource_lister.py --project my-project-id

# Run AWS script directly  
python aws-resource/aws_resource_lister.py --instances-only --s3-only
```

## Setup

Install dependencies using uv (recommended):

```bash
uv pip install -r requirements.txt
```

Or with pip:

```bash
pip install -r requirements.txt
```

For GCP scripts, you'll need to authenticate with Google Cloud:

```bash
gcloud auth application-default login
```

For AWS scripts, ensure your AWS credentials are configured (e.g., via AWS CLI or environment variables).

## Usage

### GCP Resource Lister

The GCP resource lister can enumerate various types of resources in your GCP projects:

#### List all resources in a specific project:
```bash
python main.py gcp list --project my-project-id
```

#### List only specific resource types:
```bash
# List only instances
python main.py gcp list --project my-project-id --instances-only

# List only VPC networks
python main.py gcp list --project my-project-id --vpcs-only

# List only reserved IPs
python main.py gcp list --project my-project-id --ips-only

# List only snapshots
python main.py gcp list --project my-project-id --snapshots-only

# List only disks
python main.py gcp list --project my-project-id --disks-only

# List only storage buckets
python main.py gcp list --project my-project-id --storage-only

# List only Cloud Run services
python main.py gcp list --project my-project-id --cloudrun-only
```

### Resource Details

The script provides detailed information for each resource type:

- **Compute Instances**: Name, zone, status, machine type, internal IPs, external IPs
- **VPC Networks**: Name, routing mode, number of subnets, description
- **Reserved IPs**: Name, IP address, region, status, type, purpose
- **Persistent Disks**: Name, zone, size (GB), type, status, labels
- **Snapshots**: Name, status, source disk, storage size, labels
- **Storage Buckets**: Name, location, storage class, creation date, labels
- **Cloud Run Services**: Name, location, status, URL, creation date

### Using the GCP resource tool directly:
```bash
python gcp_resources/gcp_resource_lister.py --project my-project-id
```

### AWS Resource Lister

The AWS resource lister enumerates resources across all regions and exports to CSV.

#### List all resources:
```bash
python main.py aws list
```

#### List specific resource types:
```bash
python main.py aws list --resource-types ec2_instances s3_buckets
```

#### Available resource types:
- `ec2_instances` - EC2 instances
- `ec2_volumes` - EBS volumes  
- `s3_buckets` - S3 buckets
- `rds_instances` - RDS instances
- `lambda_functions` - Lambda functions
- `security_groups` - Security groups
- `vpcs` - VPC networks

#### Direct usage with individual script:
```bash
# List all resources
python aws-resource/aws_resource_lister.py

# List only specific resource types
python aws-resource/aws_resource_lister.py --instances-only --s3-only

# Available flags:
# --instances-only    List only EC2 instances
# --vpcs-only         List only VPC networks  
# --s3-only           List only S3 buckets
# --rds-only          List only RDS instances
# --lambda-only       List only Lambda functions
# --security-groups-only  List only security groups
# --volumes-only      List only EBS volumes
```

**Notes**: 
- The AWS lister scans all regions by default
- Output is saved to `aws_inventory.csv` in the same directory as the script
- Resources that don't have creation timestamps show 'N/A' in the output
- Default AWS resources (like default VPCs) are automatically excluded from the output

## Authentication

### GCP
The script uses Google Cloud Application Default Credentials (ADC). You can authenticate in several ways:

1. Use `gcloud auth application-default login` for local development
2. Set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to a service account key file
3. Run in a GCP environment (like Cloud Shell or a GCE instance) with appropriate service account

### AWS
Ensure AWS credentials are configured via:
- AWS CLI (`aws configure`)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
- IAM roles (for EC2 instances)

## Requirements

- Python 3.13+
- Google Cloud SDK for GCP authentication
- AWS CLI for AWS authentication
- GCP libraries: `google-cloud-compute`, `google-cloud-resource-manager`, `google-cloud-storage`, `google-cloud-run`
- AWS libraries: `boto3`, `click`
- Proper IAM permissions to list resources in the target cloud accounts

## Output Format

Both scripts export data to CSV files with the following structure:

- **GCP**: `{project_id}_gcp_inventory.csv`
- **AWS**: `aws_inventory.csv`

The CSV files include resource type, name, creation time, and various resource-specific details.

## Help Commands

Get detailed help for any command:

```bash
# Main help
python main.py --help

# GCP help
python main.py gcp --help
python main.py gcp list --help

# AWS help  
python main.py aws --help
python main.py aws list --help
```