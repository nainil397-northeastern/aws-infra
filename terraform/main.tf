locals {
  vpc_cidrs = [for number in range(0, var.vpc_count) : cidrsubnet(var.cidr, 8, number)]
}

module "mynetwork" {
  source = "./module/networking"

  region                  = var.region
  environment             = var.environment
  vpc_count               = var.vpc_count
  count                   = var.vpc_count
  cidr                    = local.vpc_cidrs[count.index]
  priv_sub_count          = var.priv_sub_count
  pub_sub_count           = var.pub_sub_count
  destination_cidr        = var.destination_cidr
  ingress_cidr            = var.ingress_cidr
  public_key_loc          = var.public_key_loc
  my_ami_id               = var.my_ami_id
  instance_type           = var.instance_type
  delete_on_termination   = var.delete_on_termination
  volume_size             = var.volume_size
  volume_type             = var.volume_type
  disable_api_termination = var.disable_api_termination
  app_port                = var.app_port
  ttl_nainil              = var.ttl_nainil
  domain_name             = var.domain_name
  db_name                 = var.db_name
  db_password             = var.db_password
  db_username             = var.db_username
  nainil_certificate      = var.nainil_certificate

}
