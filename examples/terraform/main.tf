# AWS Network MCP - Lab Environment
# 
# This Terraform creates a small test environment with intentional
# misconfigurations to practice troubleshooting.
#
# COST WARNING: This creates a Transit Gateway (~$36/month) and
# two VPCs with t3.micro instances (free tier eligible).
# Run `terraform destroy` when done to avoid charges.
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply
#   # Test with the MCP server
#   terraform destroy

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-network-mcp-lab"
      Environment = "lab"
      ManagedBy   = "terraform"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# VPC A - "App" VPC
resource "aws_vpc" "app" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "mcp-lab-app-vpc"
  }
}

resource "aws_subnet" "app" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.1.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "mcp-lab-app-subnet"
  }
}

# VPC B - "DB" VPC
resource "aws_vpc" "db" {
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "mcp-lab-db-vpc"
  }
}

resource "aws_subnet" "db" {
  vpc_id            = aws_vpc.db.id
  cidr_block        = "10.2.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "mcp-lab-db-subnet"
  }
}

# Transit Gateway
resource "aws_ec2_transit_gateway" "main" {
  description                     = "MCP Lab Transit Gateway"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"

  tags = {
    Name = "mcp-lab-tgw"
  }
}

# TGW Attachments
resource "aws_ec2_transit_gateway_vpc_attachment" "app" {
  subnet_ids         = [aws_subnet.app.id]
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.app.id

  tags = {
    Name = "mcp-lab-app-attachment"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "db" {
  subnet_ids         = [aws_subnet.db.id]
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.db.id

  tags = {
    Name = "mcp-lab-db-attachment"
  }
}

# TGW Route Table
resource "aws_ec2_transit_gateway_route_table" "main" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name = "mcp-lab-tgw-rt"
  }
}

# TGW Route Table Associations
resource "aws_ec2_transit_gateway_route_table_association" "app" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

resource "aws_ec2_transit_gateway_route_table_association" "db" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.db.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# INTENTIONAL MISCONFIGURATION: Only propagate app VPC, not DB
# This will cause the path analyzer to detect missing propagation
resource "aws_ec2_transit_gateway_route_table_propagation" "app" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# Uncomment to fix the missing propagation:
# resource "aws_ec2_transit_gateway_route_table_propagation" "db" {
#   transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.db.id
#   transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
# }

# VPC Route Tables
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.app.id

  route {
    cidr_block         = "10.2.0.0/16"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }

  tags = {
    Name = "mcp-lab-app-rt"
  }
}

resource "aws_route_table_association" "app" {
  subnet_id      = aws_subnet.app.id
  route_table_id = aws_route_table.app.id
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.db.id

  route {
    cidr_block         = "10.1.0.0/16"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }

  tags = {
    Name = "mcp-lab-db-rt"
  }
}

resource "aws_route_table_association" "db" {
  subnet_id      = aws_subnet.db.id
  route_table_id = aws_route_table.db.id
}

# Security Groups
resource "aws_security_group" "app" {
  name        = "mcp-lab-app-sg"
  description = "App server security group"
  vpc_id      = aws_vpc.app.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mcp-lab-app-sg"
  }
}

resource "aws_security_group" "db" {
  name        = "mcp-lab-db-sg"
  description = "DB server security group"
  vpc_id      = aws_vpc.db.id

  # INTENTIONAL MISCONFIGURATION: Only allow port 3306, not 5432
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
    description = "MySQL from app VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mcp-lab-db-sg"
  }
}

# Outputs for testing
output "app_vpc_id" {
  description = "App VPC ID"
  value       = aws_vpc.app.id
}

output "db_vpc_id" {
  description = "DB VPC ID"
  value       = aws_vpc.db.id
}

output "tgw_id" {
  description = "Transit Gateway ID"
  value       = aws_ec2_transit_gateway.main.id
}

output "tgw_route_table_id" {
  description = "TGW Route Table ID"
  value       = aws_ec2_transit_gateway_route_table.main.id
}

output "app_subnet_id" {
  description = "App Subnet ID"
  value       = aws_subnet.app.id
}

output "db_subnet_id" {
  description = "DB Subnet ID"
  value       = aws_subnet.db.id
}

output "known_issues" {
  description = "Intentional misconfigurations for troubleshooting practice"
  value = [
    "1. DB VPC route propagation missing from TGW route table",
    "2. DB security group allows MySQL (3306) but PostgreSQL (5432) is blocked",
  ]
}
