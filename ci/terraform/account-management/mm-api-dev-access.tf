locals {
  is_dev                   = contains(["authdev1", "authdev2", "dev"], var.environment)
  mm_dev_access_count      = local.is_dev ? 1 : 0
  port_forward_doc_suffix  = "mm-api-developer-proxy-ssm-document"
  mm_proxy_instance_suffix = "mm-api-developer-proxy"
}

resource "aws_iam_role" "developer_proxy_role" {
  count = local.mm_dev_access_count

  name = "${var.environment}-developer-proxy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_policy_attachment" {
  count = local.mm_dev_access_count

  role       = aws_iam_role.developer_proxy_role[count.index].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy" "session_manager_ec2_policy" {
  count = local.mm_dev_access_count

  name = "${var.aws_region}-session-manager-ec2-policy"
}

resource "aws_iam_role_policy_attachment" "session_manager_ec2_policy" {
  count = local.mm_dev_access_count

  role       = aws_iam_role.developer_proxy_role[count.index].name
  policy_arn = data.aws_iam_policy.session_manager_ec2_policy[count.index].arn
}


data "aws_kms_alias" "ssm_key_alias" {
  count = local.mm_dev_access_count

  name = "alias/kms/${var.aws_region}-session-manager-logs-key"
}

data "aws_iam_policy_document" "developer_proxy_kms_access" {
  count = local.mm_dev_access_count

  statement {
    sid    = "AllowGetParameters"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      data.aws_kms_alias.ssm_key_alias[count.index].target_key_arn,
    ]
  }
}

resource "aws_iam_role_policy" "developer_proxy_kms_access" {
  count = local.mm_dev_access_count

  name   = "${var.environment}-developer-proxy-kms-access"
  role   = aws_iam_role.developer_proxy_role[count.index].name
  policy = data.aws_iam_policy_document.developer_proxy_kms_access[count.index].json
}

resource "aws_iam_instance_profile" "developer_proxy_profile" {
  count = local.mm_dev_access_count

  name = "${var.environment}-developer-proxy-profile"
  role = aws_iam_role.developer_proxy_role[count.index].name
}

data "aws_ami" "developer_proxy_ami" {
  count = local.mm_dev_access_count

  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}

resource "aws_ssm_document" "developer_port_forward_document" {
  count = local.mm_dev_access_count

  name          = "${var.environment}-${local.port_forward_doc_suffix}"
  document_type = "Session"

  content = <<DOC
  {
    "schemaVersion": "1.0",
    "description": "Document to start an Account Management API forwarding session over Session Manager",
    "sessionType": "Port",
    "parameters": {
      "localPortNumber": {
        "type": "String",
        "description": "(Optional) Port number on local machine to forward traffic to. An open port is chosen at run-time if not provided",
        "allowedPattern": "^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
        "default": "0"
      }
    },
    "properties": {
      "portNumber": "80",
      "type": "LocalPortForwarding",
      "localPortNumber": "{{ localPortNumber }}"
    }
  }
DOC
}

resource "aws_instance" "developer_proxy" {
  count = local.mm_dev_access_count

  ami           = data.aws_ami.developer_proxy_ami[count.index].id
  instance_type = "t4g.nano"

  subnet_id              = local.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.developer_proxy_sg[count.index].id]

  iam_instance_profile = aws_iam_instance_profile.developer_proxy_profile[count.index].name

  user_data_replace_on_change = true

  # TL;DR of user data:
  # - Update and upgrade packages
  # - Install nginx
  # - Write nginx proxy config to /etc/nginx/conf.d/api-proxy.conf
  # - Remove `ssm-user` user's sudo access
  # - Enable and start nginx
  user_data = <<-EOT
    #cloud-config
    package_update: true
    package_upgrade: true

    packages:
      - nginx

    write_files:
      - path: /etc/nginx/conf.d/api-proxy.conf
        content: |
          server {
              listen 80;
              server_name _;

              # Debug request details
              add_header X-Debug-Host $host;
              add_header X-Debug-Uri $request_uri;

              location / {
                  # This maps the request path correctly - using literal variable
                  rewrite ^/(.*) /${module.account-management-method_management_gateway.api_gateway_stage_name}/$1 break;

                  # Set the proper Host header for API Gateway
                  proxy_set_header Host ${module.account-management-method_management_gateway.api_gateway_id}.execute-api.eu-west-2.amazonaws.com;

                  # Pass the actual VPC endpoint - without https:// in proxy_pass
                  proxy_pass https://${data.aws_vpc_endpoint.auth_api_vpc_endpoint.dns_entry[0].dns_name};

                  # Forward the authorization header
                  proxy_set_header Authorization $http_authorization;
                  proxy_pass_request_headers on;

                  # Add additional headers for debugging
                  proxy_set_header X-Real-IP $remote_addr;
                  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                  proxy_set_header X-Original-URI $request_uri;

                  # SSL verification settings for connecting to VPC endpoint
                  proxy_ssl_verify off;
              }
          }
        owner: root:root
        permissions: '0644'
      - path: /etc/sudoers.d/ssm-agent-users
        content: |
          # User rules for ssm-user
        owner: root:root
        permissions: '0440'

    runcmd:
      - systemctl enable nginx
      - systemctl start nginx
  EOT

  metadata_options {
    http_tokens = "required"
  }
  monitoring = true

  tags = {
    Name = "${var.environment}-${local.mm_proxy_instance_suffix}"
  }
  #checkov:skip=CKV_AWS_135:It is!
  #checkov:skip=CKV_AWS_8:There's nothing sensitive in the user data
}

locals {
  # ssm, ssmmessages, ec2messages, logs are required for SSM session manager
  # execute-api is required for nginx to connect to the API Gateway
  # s3 is required for `dnf` to access the package repositories
  required_vpc_interface_endpoints = local.is_dev ? ["ssm", "ssmmessages", "ec2messages", "execute-api", "logs"] : []
  required_vpc_gateway_endpoints   = local.is_dev ? ["s3"] : []
}

data "aws_vpc_endpoint_service" "auth_dev_access_vpc_endpoint_services" {
  for_each = toset(local.required_vpc_interface_endpoints)

  service      = each.value
  service_type = "Interface"
}
data "aws_vpc_endpoint_service" "auth_dev_access_vpc_gateway_endpoint_services" {
  for_each = toset(local.required_vpc_gateway_endpoints)

  service      = each.value
  service_type = "Gateway"
}

data "aws_vpc_endpoint" "auth_dev_access_vpc_endpoints" {
  for_each = data.aws_vpc_endpoint_service.auth_dev_access_vpc_endpoint_services

  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = each.value.service_name
  tags = {
    Environment = local.vpc_environment
    terraform   = "di-infrastructure/core"
  }
}

data "aws_vpc_endpoint" "auth_dev_access_vpc_gateway_endpoints" {
  for_each = data.aws_vpc_endpoint_service.auth_dev_access_vpc_gateway_endpoint_services

  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = each.value.service_name
  tags = {
    Environment = local.vpc_environment
    terraform   = "di-infrastructure/core"
  }
}

resource "aws_security_group" "developer_proxy_sg" {
  count = local.mm_dev_access_count

  name        = "${var.environment}-developer-proxy-sg"
  description = "Security group for developer API proxy"
  vpc_id      = data.aws_vpc.auth_shared_vpc.id

  # Allow https access to interface-type VPC endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    description = "Allow HTTPS to ${join(",", local.required_vpc_interface_endpoints)} VPC Endpoint${length(local.required_vpc_interface_endpoints) > 1 ? "s" : ""}"
    security_groups = distinct(flatten([
      for k, v in data.aws_vpc_endpoint.auth_dev_access_vpc_endpoints : v.security_group_ids
    ]))
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    description = "Allow HTTPS to ${join(",", local.required_vpc_gateway_endpoints)} VPC Endpoint${length(local.required_vpc_gateway_endpoints) > 1 ? "s" : ""}"
    cidr_blocks = distinct(flatten([
      for k, v in data.aws_vpc_endpoint.auth_dev_access_vpc_gateway_endpoints : v.cidr_blocks
    ]))
  }
}

output "network_interface_id" {
  value = data.aws_vpc_endpoint.auth_api_vpc_endpoint.network_interface_ids
}

output "api_proxy_usage" {
  value = (
    local.is_dev ? <<-EOT

    API Proxy available for ${var.environment} environment

    You will need to have the AWS session manager plugin installed (`brew install session-manager-plugin`).

    To connect:
    aws ssm start-session \
      --target ${aws_instance.developer_proxy[0].id} \
      --document-name ${aws_ssm_document.developer_port_forward_document[0].name} \
      --parameters '{"localPortNumber":["8080"]}'

    Make API requests to:
    http://localhost:8080/endpoint

    Don't forget to include your authorization header:
    curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/update-email

    To use a different local port:
    aws ssm start-session \
      --target ${aws_instance.developer_proxy[0].id} \
      --document-name ${aws_ssm_document.developer_port_forward_document[0].name} \
      --parameters '{"localPortNumber":["9000"]}'


    Alternatively, you can use the provided script:
    ci/terraform/account-management/api-proxy.sh ${var.environment} [local-port]
  EOT
    : null
  )
}
