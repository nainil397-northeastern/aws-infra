locals {
  private_subnet_cidrs = [for netnumber in range(1, var.priv_sub_count + 1) : cidrsubnet(var.cidr, 8, netnumber)]
  public_subnet_cidrs  = [for netnumber in range(var.priv_sub_count + 1, var.priv_sub_count + var.pub_sub_count + 1) : cidrsubnet(var.cidr, 8, netnumber)]
}

data "aws_ami" "recent" {
  most_recent = true
  owners      = ["865632327924"]
}

resource "aws_vpc" "nainil" {
  cidr_block = var.cidr

  tags = {
    Name = "Main VPC"
  }

  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_subnet" "nainil_private_subnet" {
  vpc_id = aws_vpc.nainil.id

  count             = var.priv_sub_count
  cidr_block        = element(local.private_subnet_cidrs, count.index)
  availability_zone = data.aws_availability_zones.azs.names[count.index % length(data.aws_availability_zones.azs.names)]

  map_public_ip_on_launch = false

  tags = {
    Name        = "Private Subnet ${count.index + 1}"
    Environment = var.environment
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_subnet" "nainil_public_subnet" {
  vpc_id = aws_vpc.nainil.id

  count             = var.pub_sub_count
  cidr_block        = element(local.public_subnet_cidrs, count.index)
  availability_zone = data.aws_availability_zones.azs.names[count.index % length(data.aws_availability_zones.azs.names)]

  map_public_ip_on_launch = true

  tags = {
    Name        = "Public Subnet ${count.index + 1}"
    Environment = var.environment
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_internet_gateway" "nainil_internet_gateway" {
  vpc_id = aws_vpc.nainil.id

  tags = {
    Name = "Internet Gateway"
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_route_table" "nainil_public_route_table" {
  vpc_id = aws_vpc.nainil.id

  tags = {
    Name = "Public Route Table"
  }

  depends_on = [
    aws_subnet.nainil_public_subnet
  ]
}

resource "aws_route" "nainil_public_route" {
  route_table_id         = aws_route_table.nainil_public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.nainil_internet_gateway.id

  depends_on = [
    aws_route_table.nainil_public_route_table
  ]
}


resource "aws_route_table_association" "nainil_pub_rt_association" {
  count          = length(local.public_subnet_cidrs)
  subnet_id      = element(aws_subnet.nainil_public_subnet.*.id, count.index)
  route_table_id = aws_route_table.nainil_public_route_table.id

  depends_on = [
    aws_route_table.nainil_public_route_table
  ]
}

resource "aws_route_table" "nainil_private_route_table" {
  vpc_id = aws_vpc.nainil.id

  tags = {
    Name = "Private Route Table"
  }

  depends_on = [
    aws_subnet.nainil_private_subnet
  ]
}

resource "aws_route_table_association" "nainil_priv_rt_association" {
  count          = length(local.private_subnet_cidrs)
  subnet_id      = element(aws_subnet.nainil_private_subnet.*.id, count.index)
  route_table_id = aws_route_table.nainil_private_route_table.id

  depends_on = [
    aws_route_table.nainil_private_route_table
  ]
}



resource "aws_security_group" "application" {
  name   = "application"
  vpc_id = aws_vpc.nainil.id

  #Incoming traffic
  # ingress {
  #  from_port = 22
  #  to_port   = 22
  #  protocol  = "tcp"
  # cidr_blocks = [var.ingress_cidr]
  # security_groups = [aws_security_group.load_balancer.id]
  # }

  #   ingress {
  #     from_port   = 80
  #     to_port     = 80
  #     protocol    = "tcp"
  #     cidr_blocks = [var.ingress_cidr]
  #   }
  #
  #   ingress {
  #     from_port   = 443
  #     to_port     = 443
  #     protocol    = "tcp"
  #     cidr_blocks = [var.ingress_cidr]
  #   }

  ingress {
    from_port = var.app_port
    to_port   = var.app_port
    protocol  = "tcp"

    # cidr_blocks = [var.ingress_cidr]
    security_groups = [aws_security_group.load_balancer.id]

  }

  #Outgoing traffic
  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.ingress_cidr]
  }
  tags = {
    Name = "application"
  }

  depends_on = [
    aws_vpc.nainil,
    aws_security_group.load_balancer
  ]
}


resource "aws_security_group" "load_balancer" {
  name   = "load_balancer"
  vpc_id = aws_vpc.nainil.id

  #Incoming traffic
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.ingress_cidr]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.ingress_cidr]
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.ingress_cidr]
  }

  tags = {
    Name = "load_balancer"
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_kms_key" "ebs_key" {
  description              = "EBS KMS Key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 7
  enable_key_rotation      = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow administration of the key"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::865632327924:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing",
          "arn:aws:iam::865632327924:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key for EBS encryption"
        Effect = "Allow"
        Principal = {
          Service = ["ec2.amazonaws.com"]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_key" "rds_key" {
  description              = "RDS KMS Key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 7
  enable_key_rotation      = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow administration of the key"
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::865632327924:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"]
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow use of the key for RDS encryption"
        Effect = "Allow"
        Principal = {
          Service = ["rds.amazonaws.com"]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}


data "template_file" "user_data" {

  template = <<EOF

#!/bin/bash
sudo touch /etc/systemd/system/service.env
sudo sh -c "echo 'DB_USERNAME=${aws_db_instance.mysql_db.username}' >> /etc/systemd/system/service.env"
sudo sh -c "echo 'DB_HOST=${aws_db_instance.mysql_db.address}' >> /etc/systemd/system/service.env"
sudo sh -c "echo 'DB_PORT=3306' >> /etc/systemd/system/service.env"

sudo sh -c "echo 'DB_NAME=${aws_db_instance.mysql_db.db_name}' >> /etc/systemd/system/service.env"
sudo sh -c "echo 'DB_PASSWORD=${aws_db_instance.mysql_db.password}' >> /etc/systemd/system/service.env"
sudo sh -c "echo 'AWS_REGION=${var.region}' >> /etc/systemd/system/service.env"
sudo sh -c "echo 'AWS_BUCKET_NAME=${aws_s3_bucket.my_image_bucket.bucket}' >> /etc/systemd/system/service.env"

sudo systemctl start app2.service
sudo systemctl enable app2.service
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/cloudwatch-config.json

EOF

}
resource "aws_key_pair" "nainil_ec2_key" {
  key_name   = "nainil_ec2_key"
  public_key = file(var.public_key_loc)

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_launch_template" "asg_launch_config" {
  name          = "nainil_check"
  image_id      = data.aws_ami.recent.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.nainil_ec2_key.key_name

  vpc_security_group_ids = [aws_security_group.application.id]

  block_device_mappings {
    device_name = data.aws_ami.recent.root_device_name
    ebs {
      volume_size           = var.volume_size
      volume_type           = var.volume_type
      delete_on_termination = var.delete_on_termination
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs_key.arn
    }

  }


  user_data = base64encode(data.template_file.user_data.rendered)


  iam_instance_profile {
    name = aws_iam_instance_profile.my_profile.name
  }

  disable_api_termination = var.disable_api_termination


  depends_on = [
    aws_key_pair.nainil_ec2_key,
    aws_security_group.application,
    aws_iam_instance_profile.my_profile,
    aws_kms_key.ebs_key

  ]
}

#
# resource "aws_instance" "nainil_aws" {
#   #ami                        = var.my_ami_id
#   ami                         = data.aws_ami.recent.id
#   instance_type               = var.instance_type
#   key_name                    = aws_key_pair.nainil_ec2_key.key_name
#   subnet_id                   = aws_subnet.nainil_public_subnet[0].id
#   associate_public_ip_address = true
#
#   user_data = <<EOF
#
# #!/bin/bash
# sudo touch /etc/systemd/system/service.env
# sudo sh -c "echo 'DB_USERNAME=${aws_db_instance.mysql_db.username}' >> /etc/systemd/system/service.env"
# sudo sh -c "echo 'DB_HOST=${aws_db_instance.mysql_db.address}' >> /etc/systemd/system/service.env"
# sudo sh -c "echo 'DB_PORT=3306' >> /etc/systemd/system/service.env"
#
# sudo sh -c "echo 'DB_NAME=${aws_db_instance.mysql_db.db_name}' >> /etc/systemd/system/service.env"
# sudo sh -c "echo 'DB_PASSWORD=${aws_db_instance.mysql_db.password}' >> /etc/systemd/system/service.env"
# sudo sh -c "echo 'AWS_REGION=${var.region}' >> /etc/systemd/system/service.env"
# sudo sh -c "echo 'AWS_BUCKET_NAME=${aws_s3_bucket.my_image_bucket.bucket}' >> /etc/systemd/system/service.env"
#
#
# sudo systemctl start app2.service
# sudo systemctl enable app2.service
#
# sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/cloudwatch-config.json
#
#
# EOF
#
#   iam_instance_profile = aws_iam_instance_profile.my_profile.id
#   #   security_groups = ["application_security_group"]
#   vpc_security_group_ids = [aws_security_group.application.id]
#
#   disable_api_termination = var.disable_api_termination
#   root_block_device {
#     volume_size           = var.volume_size
#     volume_type           = var.volume_type
#     delete_on_termination = var.delete_on_termination
#   }
#
#   tags = {
#     Name = "EC2 Instance ${timestamp()}"
#   }
#
#   depends_on = [
#     aws_subnet.nainil_public_subnet,
#     aws_security_group.application
#   ]
#
# }


resource "aws_autoscaling_group" "asg_launch_config" {
  name                = "asg_launch_config"
  min_size            = 1
  max_size            = 3
  desired_capacity    = 1
  default_cooldown    = 60
  vpc_zone_identifier = [for subnet in aws_subnet.nainil_public_subnet : subnet.id]

  launch_template {
    id      = aws_launch_template.asg_launch_config.id
    version = aws_launch_template.asg_launch_config.latest_version
  }

  target_group_arns = [aws_lb_target_group.webapp_target_group.arn]

  depends_on = [
    aws_subnet.nainil_public_subnet,
    aws_launch_template.asg_launch_config,
    aws_lb_target_group.webapp_target_group
  ]
}

resource "aws_db_subnet_group" "my_db_subnet" {
  name       = "my_db_subnet"
  subnet_ids = [aws_subnet.nainil_private_subnet[1].id, aws_subnet.nainil_private_subnet[2].id]

  tags = {
    Name = "My DB subnet group"
  }

  depends_on = [
    aws_subnet.nainil_private_subnet
  ]
}


#Autoscalling Policy
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.asg_launch_config.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.asg_launch_config.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "scaleDown" {
  alarm_name          = "terraform-scaleDown"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "15"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg_launch_config.name
  }
  alarm_description         = "Scale Down when average cpu is below 15%"
  alarm_actions             = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_metric_alarm" "scaleUp" {
  alarm_name          = "terraform-scaleUp"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "25"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg_launch_config.name
  }
  alarm_description         = "Scale Up when average cpu is above 25%"
  alarm_actions             = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]
  insufficient_data_actions = []
}


resource "aws_lb" "temp_lb" {
  name               = "temp-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [for subnet in aws_subnet.nainil_public_subnet : subnet.id]

  tags = {
    Name = "webapp_lb"
  }

  depends_on = [
    aws_security_group.load_balancer,
    aws_subnet.nainil_public_subnet
  ]
}

resource "aws_lb_listener" "temp_lb_listener" {
  load_balancer_arn = aws_lb.temp_lb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.nainil_certificate

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webapp_target_group.arn
  }
  depends_on = [
    aws_lb.temp_lb,
    aws_lb_target_group.webapp_target_group
  ]
}

resource "aws_lb_target_group" "webapp_target_group" {
  name_prefix = "webapp"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.nainil.id
  target_type = "instance"

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthz"
    port                = "8080"
    matcher             = "200"
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_cloudwatch_log_group" "csye6225" {
  name = "csye6225"
}

resource "aws_db_instance" "mysql_db" {
  identifier           = "csye6225"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 10
  username             = var.db_username
  password             = var.db_password
  db_subnet_group_name = aws_db_subnet_group.my_db_subnet.name
  db_name              = var.db_name
  multi_az             = false
  # security_group_names = aws_security_group.database.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.my_parameter_group.name
  apply_immediately      = true
  skip_final_snapshot    = true
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_key.arn
  depends_on = [
    aws_db_subnet_group.my_db_subnet,
    aws_db_parameter_group.my_parameter_group,
    aws_security_group.database,
    aws_kms_key.rds_key
  ]
}

resource "aws_security_group" "database" {
  name   = "database"
  vpc_id = aws_vpc.nainil.id


  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }
  # egress {
  #  from_port       = 0
  #   protocol        = "-1"
  #   to_port         = 0
  #   cidr_blocks     = [var.ingress_cidr]
  #   security_groups = [aws_security_group.application.id]
  # }
  tags = {
    Name = "database"
  }

  depends_on = [
    aws_vpc.nainil
  ]
}

resource "aws_db_parameter_group" "my_parameter_group" {
  name   = "rds-pg"
  family = "mysql8.0"

  parameter {
    name  = "character_set_server"
    value = "utf8"
  }

  parameter {
    name  = "character_set_client"
    value = "utf8"
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_vpc.nainil
  ]
}


resource "random_id" "bucket_id" {
  byte_length = 8
}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "my_image_bucket" {
  bucket = "${var.environment}-${random_id.bucket_id.hex}"

  force_destroy = true

  depends_on = [
    random_id.bucket_id
  ]
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.my_image_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [
    aws_s3_bucket.my_image_bucket
  ]
}

resource "aws_s3_bucket_acl" "my_bucket_acl" {
  bucket = aws_s3_bucket.my_image_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.my_image_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "versioning-bucket-config" {
  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.versioning]

  bucket = aws_s3_bucket.my_image_bucket.id

  rule {
    id = "config"

    filter {
      prefix = "config/"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mySecurity" {
  bucket = aws_s3_bucket.my_image_bucket.id

  rule {
    apply_server_side_encryption_by_default {

      sse_algorithm = "AES256"
    }
  }

  depends_on = [
    aws_kms_key.mykey,
    aws_s3_bucket.my_image_bucket
  ]
}


resource "aws_iam_role" "EC2-CSYE6225" {
  name                = "EC2-CSYE6225"
  assume_role_policy  = data.aws_iam_policy_document.instance_assume_role_policy.json
  managed_policy_arns = [aws_iam_policy.WebAppS3.arn, aws_iam_policy.cloudwatch_agent_policy.arn]

  depends_on = [
    data.aws_iam_policy_document.instance_assume_role_policy,
    aws_iam_policy.WebAppS3,
    aws_iam_policy.cloudwatch_agent_policy

  ]
}

resource "aws_iam_policy" "cloudwatch_agent_policy" {
  name = "CloudWatchAgentPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = ["*"]
      },
    ]
  })
}


# output "public_ip" {
#   value = aws_instance.nainil_aws.public_ip
# }

data "aws_route53_zone" "main" {
  name         = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "web" {
  name    = var.domain_name
  type    = "A"
  zone_id = data.aws_route53_zone.main.zone_id

  alias {
    name                   = aws_lb.temp_lb.dns_name
    zone_id                = aws_lb.temp_lb.zone_id
    evaluate_target_health = true
  }
  #ttl = var.ttl_nainil
  #   records = [
  #     aws_instance.nainil_aws.public_ip,
  #   ]

  depends_on = [
    # aws_instance.nainil_aws,
    data.aws_route53_zone.main,
    aws_lb.temp_lb
  ]
}


# resource "aws_iam_role_policy_attachment" "some_bucket_policy" {
#   role       = aws_iam_role.some_role.name
#   policy_arn = aws_iam_policy.bucket_policy.arn
# }

# resource "aws_s3_bucket_policy" "s3Policy" {
#   bucket = aws_s3_bucket.my_image_bucket.id
#   policy = jsonencode({
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Action": [
#               "s3:PutObject",
#               "s3:GetObject",
#               "s3:ListBucket",
#               "s3:DeleteObject"
#             ],
#             "Effect": "Allow",
#             "Resource": [
#                 "arn:aws:s3:::${aws_s3_bucket.my_image_bucket.bucket}",
#                 "arn:aws:s3:::${aws_s3_bucket.my_image_bucket.bucket}/*"
#             ]
#         }
#     ]})

#     depends_on = [
#       aws_s3_bucket.my_image_bucket
#     ]
# }

resource "aws_iam_policy" "WebAppS3" {
  name = "WebAppS3"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::${aws_s3_bucket.my_image_bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.my_image_bucket.bucket}/*"
        ]
      }
  ] })

  depends_on = [
    aws_s3_bucket.my_image_bucket
  ]
}

data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_instance_profile" "my_profile" {
  name = "my-profile"
  role = aws_iam_role.EC2-CSYE6225.name

  depends_on = [
    aws_iam_role.EC2-CSYE6225
  ]
}





