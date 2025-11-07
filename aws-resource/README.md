# AWS Resource Management Tools

A collection of Python tools to manage AWS resources with configurable preservation rules.

## Features

### AWS Resource Cleaner
- Delete specific AWS resources in specified regions
- Exclude specific resources from deletion (by region or globally)
- Support for multiple resource types:
  - EC2 instances
  - EC2 volumes
  - EC2 snapshots
  - S3 buckets
  - Lambda functions
  - RDS instances
- Dry-run mode to preview what would be deleted
- Safety confirmation prompts

### AWS Resource Lister
- List AWS resources across regions and export to CSV
- Support for multiple resource types:
  - EC2 instances
  - EC2 volumes
  - EC2 snapshots
  - S3 buckets
  - Lambda functions
  - RDS instances
  - Elastic IPs
  - Security Groups
- Filter by specific regions
- Export complete resource inventory to CSV for auditing

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Configure your AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (if running on EC2)

## Configuration

Create a `config.json` file to specify resources that should NOT be deleted. The format is:

```json
{
  "excluded_resources": {
    "all_regions": {
      "ec2_instances": [
        "i-1234567890abcdef0"
      ],
      "s3_buckets": [
        "my-important-bucket"
      ]
    },
    "us-east-1": {
      "lambda_functions": [
        "critical-function"
      ]
    }
  }
}
```

## Usage

### AWS Resource Cleaner

Basic usage to delete EC2 instances in all regions:

```bash
python aws_resource_cleaner.py -r ec2_instances
```

Delete multiple resource types in specific regions:

```bash
python aws_resource_cleaner.py -r ec2_instances -r ec2_volumes -r s3_buckets --regions us-east-1 eu-west-1
```

Dry-run mode (shows what would be deleted without actually deleting):

```bash
python aws_resource_cleaner.py -r ec2_instances --dry-run
```

Use custom configuration file:

```bash
python aws_resource_cleaner.py -r ec2_instances -c my_config.json
```

### AWS Resource Lister

List EC2 instances in all regions and export to CSV:

```bash
python aws_resource_lister.py -r ec2_instances -o ec2_inventory.csv
```

List multiple resource types in specific regions:

```bash
python aws_resource_lister.py -r ec2_instances -r lambda_functions --regions us-east-1 eu-west-1 -o resources.csv
```

List all supported resources in all regions:

```bash
python aws_resource_lister.py -r ec2_instances -r ec2_volumes -r ec2_snapshots -r s3_buckets -r lambda_functions -r rds_instances -r elastic_ips -r security_groups --include-all-regions -o full_inventory.csv
```

## Supported Resource Types

### For aws_resource_cleaner.py:
- `ec2_instances`: EC2 virtual machines
- `ec2_volumes`: EBS volumes
- `ec2_snapshots`: EBS snapshots
- `s3_buckets`: S3 storage buckets
- `lambda_functions`: Lambda serverless functions
- `rds_instances`: RDS database instances

### For aws_resource_lister.py:
- `ec2_instances`: EC2 virtual machines
- `ec2_volumes`: EBS volumes
- `ec2_snapshots`: EBS snapshots
- `s3_buckets`: S3 storage buckets
- `lambda_functions`: Lambda serverless functions
- `rds_instances`: RDS database instances
- `elastic_ips`: Elastic IP addresses
- `security_groups`: Security groups

## Safety Warnings

⚠️ **WARNING**: These tools interact with your AWS resources. Use with caution!

### For aws_resource_cleaner.py:
- This tool will permanently delete your AWS resources
- Always run with `--dry-run` first to see what would be deleted
- Make sure your `config.json` correctly specifies resources to preserve
- Test on non-critical resources first
- Use AWS IAM policies with minimal necessary permissions

### For aws_resource_lister.py:
- This tool only reads resource information and exports to CSV
- No destructive operations are performed

## License

This project is licensed under the MIT License.