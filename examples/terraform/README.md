# Lab environment

The Terraform lab for this server lives in the companion repository:

https://github.com/harin-singh/aws-hybrid-network-landing-zone

`examples/complete` there deploys the hub-and-spoke topology this MCP server
models offline: segmented Transit Gateway route tables, inspection VPC with
AWS Network Firewall (`STRICT_ORDER` + `aws:drop_established`), and a BGP
Site-to-Site VPN advertising `10.200.0.0/16`.

```bash
git clone https://github.com/harin-singh/aws-hybrid-network-landing-zone.git
cd aws-hybrid-network-landing-zone/examples/complete
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

After apply, point this MCP server at the same account/region (omit
`AWS_NETWORK_MCP_DEMO`) and use `explain_connectivity` against the spoke
and on-prem test IPs. Destroy the stack when finished; idle cost is
documented in that repository's README.
