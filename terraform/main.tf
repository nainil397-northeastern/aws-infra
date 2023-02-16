# locals {
#   vpc_cidrs = [for number in range(0, "${var.vpc_count}") : cidrsubnet("${var.cidr}", 8, number)]
# }

module "myNetwork" {
  count  = var.vpc_count
  source = "./module/networking"
  # cidr   = local.vpc_cidrs[count.index]
  cidr = var.cidr

  priv_sub_count = var.priv_sub_count
  pub_sub_count  = var.pub_sub_count
  region         = var.region
  environment    = var.environment

}
