# Azure Networking Tooling

Tools for auditing Azure Virtual Networks (VNets), address space allocations, and connected resource density.

## `vnet_inventory_and_density.py`
Audits Azure VNets across subscriptions:
- Extracts CIDR address prefixes and subnet configurations.
- Calculates connected device density (Network Interfaces / NICs attached to subnets).
- Identifies **Abandoned / Unused VNets (0 NICs)** to guide decommission planning and reduce attack surfaces.

### Usage
```bash
python vnet_inventory_and_density.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --format table

# Show only unused / abandoned VNets
python vnet_inventory_and_density.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --show-abandoned-only \
  --format table
```
