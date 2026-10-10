# GCP Networking Tooling

Tools for auditing Google Cloud VPC network topologies, subnet allocations, and peering architectures.

## `vpc_network_inventory.py`
Discovers VPC networks across Google Cloud projects:
- Identifies **Auto-Mode vs Custom-Mode** VPC configurations.
- Counts subnets and aggregates primary CIDR allocations.
- Reports regional vs global dynamic routing configuration.
- Identifies VPC Network Peering connections.

### Usage
```bash
python vpc_network_inventory.py --project-id "my-gcp-project" --format table

python vpc_network_inventory.py \
  --project-id "prod-network-hub,stage-network-spoke" \
  --format csv \
  --output-file output/gcp_networks.csv
```
