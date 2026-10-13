############################################
# VPC, subnets, routing
############################################

resource "aws_vpc" "lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "cloud-security-lab-vpc" }
}

# Fix for CKV2_AWS_12: the VPC's default security group allows nothing.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.lab_vpc.id
  # no ingress / egress blocks = deny all
  tags = { Name = "lab-default-sg-deny-all" }
}

resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  # Fix for CKV_AWS_130: no automatic public IPs. The one instance that needs
  # internet reachability gets an explicit Elastic IP below.
  map_public_ip_on_launch = false

  tags = { Name = "lab-public-subnet" }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "lab-private-subnet" }
}

resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "lab-igw" }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab_igw.id
  }

  tags = { Name = "lab-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# The private subnet intentionally has no route to the Internet Gateway.

############################################
# VPC Flow Logs (fix for CKV2_AWS_11)
############################################

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/lab/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lab.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow_logs_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "lab-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_permissions.json
}

resource "aws_flow_log" "lab" {
  vpc_id               = aws_vpc.lab_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
}

############################################
# Security Group - least privilege in AND out
############################################

resource "aws_security_group" "lab_sg" {
  name        = "lab-instance-sg"
  description = "Admin-only SSH/HTTP in, HTTPS-only out"
  vpc_id      = aws_vpc.lab_vpc.id

  ingress {
    description = "SSH from administrator IP only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
  }

  # Fix for CKV_AWS_260: the test web page is no longer world-readable.
  ingress {
    description = "HTTP test page from administrator IP only"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
  }

  # Fix for CKV_AWS_382: egress limited to HTTPS (package repos, SSM, AWS APIs).
  egress {
    description = "HTTPS out"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "lab-instance-sg" }
}

############################################
# Network ACL - stateless second layer (must also allow return traffic)
############################################

resource "aws_network_acl" "public_nacl" {
  vpc_id     = aws_vpc.lab_vpc.id
  subnet_ids = [aws_subnet.public_subnet.id]

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.admin_ip_cidr
    from_port  = 22
    to_port    = 22
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.admin_ip_cidr
    from_port  = 80
    to_port    = 80
  }

  # Return traffic for the instance's outbound HTTPS (Linux ephemeral ports).
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 32768
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Replies to the administrator's SSH / HTTP sessions.
  egress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.admin_ip_cidr
    from_port  = 1024
    to_port    = 65535
  }

  tags = { Name = "lab-public-nacl" }
}

############################################
# EC2 instance (was missing from the baseline Terraform, which only defined
# the security group - found while scanning: CKV2_AWS_5)
############################################

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_iam_policy_document" "instance_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "lab-instance-role"
  assume_role_policy = data.aws_iam_policy_document.instance_assume.json
}

# Only permission the instance role gets: Systems Manager core (Session Manager,
# patching). No S3 access - the Capital One lesson.
resource "aws_iam_role_policy_attachment" "instance_ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "lab-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "lab" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.lab_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  monitoring             = true
  ebs_optimized          = true

  # IMDSv2 only: session token required, hop limit 1. This is the control that
  # would have broken the Capital One SSRF -> credential theft step.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.lab.arn
    volume_type = "gp3"
  }

  tags = { Name = "lab-instance" }
}

resource "aws_eip" "lab" {
  domain   = "vpc"
  instance = aws_instance.lab.id
  tags     = { Name = "lab-instance-eip" }

  depends_on = [aws_internet_gateway.lab_igw]
}
