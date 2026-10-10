# AWS VPC Network & Resource Tooling

Tools for auditing VPC topology, network architecture, and resource attachment density across AWS regions.

## Scripts

### 1. `vpc_network_inventory.py`
Discovers all VPCs across AWS accounts and active regions:
- Extracts CIDR blocks, Subnet counts, Attached Internet Gateways (IGWs), and default VPC status.
- Exports to console table, CSV, or JSON.

```bash
# Scan VPCs across default regions
python vpc_network_inventory.py --format table

# Scan specific regions and write CSV
python vpc_network_inventory.py \
  --regions "us-east-1,us-west-2,eu-west-1" \
  --format csv \
  --output-file output/vpc_inventory.csv
```

### 2. `vpc_density_analyzer.py`
Audits network interface density (ENIs) per VPC to measure cloud infrastructure utilization:
- Categorizes ENIs into EC2 instances, Lambda VPC interfaces, RDS databases, NAT Gateways, and Load Balancers.
- Automatically flags **Abandoned / Unused VPCs (0 ENIs)** to identify deprecation candidates and reduce exposure.
- Identifies VPCs with high resource density.

```bash
# Analyze ENI density across all production profiles
python vpc_density_analyzer.py --profile-pattern "prod"

# Filter strictly for abandoned (zero-attachment) VPCs
python vpc_density_analyzer.py --show-abandoned-only --format table
```
