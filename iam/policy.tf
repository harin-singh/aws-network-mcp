# IAM Policy for AWS Network MCP Server
# Read-only access for network troubleshooting

resource "aws_iam_policy" "aws_network_mcp_readonly" {
  name        = "AWSNetworkMCPReadOnly"
  description = "Read-only access for AWS Network MCP troubleshooting server"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2NetworkReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeTransitGatewayRouteTables",
          "ec2:DescribeTransitGatewayVpcAttachments",
          "ec2:GetTransitGatewayRouteTableAssociations",
          "ec2:GetTransitGatewayRouteTablePropagations",
          "ec2:SearchTransitGatewayRoutes",
          "ec2:DescribeVpnConnections",
          "ec2:DescribeVpnGateways",
          "ec2:DescribeCustomerGateways",
          "ec2:DescribeManagedPrefixLists",
          "ec2:GetManagedPrefixListEntries",
        ]
        Resource = "*"
      },
      {
        Sid    = "DirectConnectReadOnly"
        Effect = "Allow"
        Action = [
          "directconnect:DescribeVirtualInterfaces",
          "directconnect:DescribeConnections",
          "directconnect:DescribeDirectConnectGateways",
          "directconnect:DescribeDirectConnectGatewayAttachments",
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53ResolverReadOnly"
        Effect = "Allow"
        Action = [
          "route53resolver:ListResolverEndpoints",
          "route53resolver:ListResolverEndpointIpAddresses",
          "route53resolver:ListResolverRules",
          "route53resolver:ListResolverRuleAssociations",
          "route53resolver:GetResolverEndpoint",
          "route53resolver:GetResolverRule",
        ]
        Resource = "*"
      },
      {
        Sid    = "NetworkFirewallReadOnly"
        Effect = "Allow"
        Action = [
          "network-firewall:ListFirewalls",
          "network-firewall:DescribeFirewall",
          "network-firewall:DescribeFirewallPolicy",
          "network-firewall:DescribeRuleGroup",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogsQuery"
        Effect = "Allow"
        Action = [
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:DescribeLogGroups",
        ]
        Resource = "*"
      },
    ]
  })
}

# Optional: Reachability Analyzer policy (incurs per-analysis cost)
resource "aws_iam_policy" "aws_network_mcp_reachability" {
  name        = "AWSNetworkMCPReachabilityAnalyzer"
  description = "Reachability Analyzer access for AWS Network MCP (incurs ~$0.10 per analysis)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReachabilityAnalyzerAccess"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInsightsPath",
          "ec2:DeleteNetworkInsightsPath",
          "ec2:StartNetworkInsightsAnalysis",
          "ec2:DescribeNetworkInsightsPaths",
          "ec2:DescribeNetworkInsightsAnalyses",
        ]
        Resource = "*"
      },
    ]
  })
}

# IAM Role for the MCP server
resource "aws_iam_role" "aws_network_mcp" {
  name = "AWSNetworkMCPRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.aws_network_mcp.name
  policy_arn = aws_iam_policy.aws_network_mcp_readonly.arn
}

# Uncomment to add Reachability Analyzer support
# resource "aws_iam_role_policy_attachment" "reachability" {
#   role       = aws_iam_role.aws_network_mcp.name
#   policy_arn = aws_iam_policy.aws_network_mcp_reachability.arn
# }

output "policy_arn" {
  description = "ARN of the read-only policy"
  value       = aws_iam_policy.aws_network_mcp_readonly.arn
}

output "role_arn" {
  description = "ARN of the IAM role"
  value       = aws_iam_role.aws_network_mcp.arn
}
