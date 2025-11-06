# Scripts

This repository contains various utility scripts for cloud resource management.

## Available Scripts

- `main.py` - Main entry point for cloud resource management tools
- `gcp_resources/` - Directory containing GCP resource management tools
  - `gcp_resource_lister.py` - Lists GCP resources (instances, VPCs, reserved IPs)
  - `gcp_resource_tool.py` - Wrapper for GCP resource management tools
- `aws-resource-cleaner/` - Directory containing AWS resource management tools

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
```

### Resource Details

The script provides detailed information for each resource type:

- **Compute Instances**: Name, zone, status, machine type, internal IPs, external IPs
- **VPC Networks**: Name, routing mode, number of subnets, description
- **Reserved IPs**: Name, IP address, region, status, type, purpose

### Using the GCP resource tool directly:
```bash
python -m gcp_resources.gcp_resource_tool list --project my-project-id
```

Or run the package as a module:
```bash
python -m gcp_resources list --project my-project-id
```

## Authentication

The script uses Google Cloud Application Default Credentials (ADC). You can authenticate in several ways:

1. Use `gcloud auth application-default login` for local development
2. Set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to a service account key file
3. Run in a GCP environment (like Cloud Shell or a GCE instance) with appropriate service account

## Requirements

- Python 3.13+
- Google Cloud SDK for authentication
- Proper IAM permissions to list resources in the target GCP project