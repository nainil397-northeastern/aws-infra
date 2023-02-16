variable "cidr" {
  type        = string
  description = "CIDR for the VPC"
  //default     = "10.0.0.0/16"
}

variable "priv_sub_count" {
  type        = string
  description = "Count of the total number of private subnets"
 // default     = "3"
}

variable "pub_sub_count" {
  type        = string
  description = "Count of the total number of public subnets"
  //default     = "3"
}

variable "region" {
  description = "Region for the VPC, subnets, gateway, route tables, etc."
  //default     = "us-east-1"
}

variable "environment" {
  description = "Environment of deployment"
  //default     = "dev"
}

data "aws_availability_zones" "azs" {}
