variable "cidr" {
  type        = string
  description = "CIDR for the VPC"
 // default     = "10.0.0.0/8"
}

variable "vpc_count" {
  type        = string
  description = "Count of total number of VPCs"
 // default     = "1"
}

variable "priv_sub_count" {
  type        = string
  description = "Count number of private subnets"
  //default     = "3"
}

variable "pub_sub_count" {
  type        = string
  description = "Count total public subnets"
  //default     = "3"
}

variable "region" {
  description = "Region for the VPC, subnets, gateway, route tables "
  //default     = "us-east-1"
}

variable "environment" {
  description = " deployment environment "
 // default     = "dev"
}

data "aws_availability_zones" "azs" {}
