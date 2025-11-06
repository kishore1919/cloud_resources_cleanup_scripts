# GCP Resource Lister

A script to list Google Cloud Platform (GCP) resources including compute instances, VPC networks, and reserved IP addresses.

## Prerequisites

Before running this script, you need to set up authentication to access GCP resources:

1. Install the Google Cloud CLI: [https://cloud.google.com/sdk/docs/install](https://cloud.google.com/sdk/docs/install)
2. Run `gcloud auth application-default login` to authenticate
3. Alternatively, set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to your service account key file

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic usage (lists all resource types):
```bash
python gcp_resource_lister.py
```

### Specify a project ID:
```bash
python gcp_resource_lister.py --project my-gcp-project-id
```

### List only specific resource types:
```bash
# Only instances
python gcp_resource_lister.py --instances-only

# Only VPC networks
python gcp_resource_lister.py --vpcs-only

# Only reserved IP addresses
python gcp_resource_lister.py --ips-only

# Instances for a specific project
python gcp_resource_lister.py --project my-gcp-project-id --instances-only
```

## Features

- Lists all compute instances with their status, zone, machine type, and IP addresses
- Shows VPC network details including routing mode and number of subnets
- Displays reserved IP addresses with their region, status, and type
- Handles authentication and error scenarios gracefully
- Provides a user-friendly table format for results

## Requirements

- Python 3.13+
- Google Cloud SDK with authentication configured
- Appropriate permissions to list resources in the target GCP project