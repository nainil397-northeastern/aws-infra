variable "region" {
  type        = string
  description = "Region for the VPC, subnets, gateway, route tables, etc."
  # default     = "us-east-1"

  validation {
    condition     = length(var.region) > 0
    error_message = "Please specify a region"
  }
}

variable "environment" {
  type        = string
  description = "Environment of deployment"
  # default     = "dev"

  validation {
    condition     = length(var.environment) > 0
    error_message = "Please specify an environment"
  }
}

variable "cidr" {
  type        = string
  description = "CIDR block for the VPC"
  # default     = "10.0.0.0/16"

  #validation {
   # condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(|1[6-9]|2[0-8]))$", var.cidr))
    #error_message = "CIDR block parameter must be of the format x.x.x.x/16-28."
  #}
}

variable "vpc_count" {
  type        = number
  description = "Count of the total number of VPCs"
  # default     = 1

  validation {
    condition     = var.vpc_count > 0
    error_message = "Please specify number of VPCs"
  }
}

variable "priv_sub_count" {
  type        = number
  description = "Count of the total number of private subnets"
  # default     = 3

  validation {
    condition     = var.priv_sub_count > 0
    error_message = "Please specify number of private subnets"
  }
}

variable "pub_sub_count" {
  type        = number
  description = "Count of the total number of public subnets"
  # default     = 3

  validation {
    condition     = var.pub_sub_count > 0
    error_message = "Please specify number of public subnets"
  }
}

variable "destination_cidr" {
  type        = string
  description = "The destination CIDR for public subnet"
  # default     = "0.0.0.0/0"
}


variable "ingress_cidr" {
  type        = string
  description = "CIDR for ingress"
  default     = "0.0.0.0/0"
}

variable "public_key_loc" {
  type        = string
  description = "Location of public key"
  default     = "C:\\Users\\User\\.ssh\\ec2-2202.pub"
}

variable "my_ami_id" {
  type        = string
  description = "Enter your custom AMI ID"
}

variable "instance_type" {
  type        = string
  description = "Enter Instance Type"
  default     = "t2.micro"
}

variable "delete_on_termination" {
  type    = bool
  default = true
}

variable "volume_size" {
  type    = number
  default = 50
}

variable "volume_type" {
  type    = string
  default = "gp2"
}

variable "disable_api_termination" {
  type    = bool
  default = false
}

variable "app_port" {
  type    = number
  default = 8080
}

data "aws_availability_zones" "azs" {}



