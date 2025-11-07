# Scripts

This repository contains various utility scripts for cloud resource management.

## Available Scripts

- `main.py` - Main entry point for cloud resource management tools
- `gcp_resources/` - Directory containing GCP resource management tools
  - `gcp_resource_lister.py` - Lists GCP resources (instances, VPCs, reserved IPs)
  - `gcp_resource_tool.py` - Wrapper for GCP resource management tools
- `aws-resource/` - Directory containing AWS resource management tools
  - `aws_resource_cleaner.py` - Deletes AWS resources region by region, skipping defaults
  - `aws_resource_lister.py` - Lists AWS resources and exports to CSV
  - `config.json` - JSON configuration file for AWS cleanup settings (excluded resources by region)

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
python -m gcp_resources.gcp_resource_tool list --project my-project-id
```

Or run the package as a module:
```bash
python -m gcp_resources list --project my-project-id
```

### AWS Resource Cleaner

The AWS resource cleaner deletes resources across regions, skipping default resources by default. It supports various AWS services and requires confirmation for each deletion.

#### Clean all resources in all regions (skipping defaults):
```bash
python -m aws_resource_cleaner.aws_resource_cleaner
```

#### Clean specific resource types:
```bash
python -m aws_resource_cleaner.aws_resource_cleaner -r ec2_instances -r s3_buckets
```

#### Clean in specific regions:
```bash
python -m aws_resource_cleaner.aws_resource_cleaner --regions us-east-1 us-west-2
```

#### Dry run (show what would be deleted without deleting):
```bash
python -m aws_resource_cleaner.aws_resource_cleaner --dry-run
```

#### Include default resources (not recommended):
```bash
python -m aws_resource_cleaner.aws_resource_cleaner --no-skip-defaults
```

Supported resource types: ec2_instances, ec2_volumes, ec2_snapshots, s3_buckets, lambda_functions, rds_instances, ecs_clusters, elb, nat_gateways, eips, security_groups, vpcs, kms_keys

### AWS Resource Lister

The AWS resource lister enumerates resources across regions and exports to CSV.

#### List all resources in all regions:
```bash
python -m aws_resource_cleaner.aws_resource_lister
```

#### List specific resource types:
```bash
python -m aws_resource_cleaner.aws_resource_lister -r ec2_instances -r s3_buckets
```

#### List in specific regions:
```bash
python -m aws_resource_cleaner.aws_resource_lister --regions us-east-1 us-west-2
```

#### Export to custom CSV file:
```bash
python -m aws_resource_cleaner.aws_resource_lister -o my_resources.csv
```

## Configuration

### AWS Cleanup Configuration

Use `config.json` to specify resources to exclude from deletion. The configuration is a JSON object with an `excluded_resources` key containing regions and resource types to preserve.

- Use `"all_regions"` to exclude resources across all regions.
- Specify region names (e.g., `"us-east-1"`) to exclude resources only in that region.
- Under each region, list resource types with arrays of resource IDs or names to preserve.

Example `config.json`:

```json
{
  "excluded_resources": {
    "all_regions": {
      "ec2_instances": [
        "i-1234567890abcdef0",
        "i-0987654321fedcba0"
      ],
      "s3_buckets": [
        "my-important-bucket",
        "company-backups"
      ]
    },
    "us-east-1": {
      "lambda_functions": [
        "critical-function-us-east-1"
      ],
      "rds_instances": [
        "production-db"
      ]
    }
  }
}
```

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
- AWS libraries: `boto3`
- Proper IAM permissions to list/delete resources in the target cloud accounts