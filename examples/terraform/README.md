# AWS Network MCP - Lab Environment

This Terraform creates a small test environment with **intentional misconfigurations** to practice network troubleshooting with the MCP server.

## Cost Warning

This creates resources that will incur AWS charges:

| Resource | Approximate Cost |
|----------|------------------|
| Transit Gateway | ~$36/month |
| 2 VPCs with subnets | Free |
| No EC2 instances by default | Free |

**Run `terraform destroy` when done to avoid ongoing charges.**

## Usage

```bash
# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Create the lab environment
terraform apply

# Note the output values for testing
# app_vpc_id, db_vpc_id, tgw_route_table_id, etc.

# Test with the MCP server
python -m aws_network_mcp.server
# Then use describe_path or tgw_route_lookup tools

# Clean up when done
terraform destroy
```

## Intentional Misconfigurations

This lab includes the following issues for troubleshooting practice:

1. **Missing TGW Route Propagation**: The DB VPC attachment is not propagating routes to the TGW route table. Traffic from App VPC to DB VPC will fail routing.

2. **Wrong Port in Security Group**: The DB security group allows MySQL (3306) but not PostgreSQL (5432). If your app uses PostgreSQL, the security group will block it.

## Troubleshooting Practice

After deploying, try these queries with the MCP server:

```
# Check TGW route table for DB VPC CIDR
tgw_route_lookup(tgw_route_table_id="<from output>", destination_cidr="10.2.0.0/16")

# Explain connectivity between VPCs
explain_connectivity(source_ip="10.1.1.100", dest_ip="10.2.1.100", port=5432)
```

## Fixing the Issues

To fix issue #1 (TGW propagation), uncomment this in `main.tf`:

```hcl
resource "aws_ec2_transit_gateway_route_table_propagation" "db" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.db.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}
```

To fix issue #2 (security group port), update the ingress rule to allow 5432.
