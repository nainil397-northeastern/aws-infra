# aws-infra

 
Infrastructure as a code with Terraform - Nainil Maladkar

This Terraform code block can be used for infrastructure setup and tear down.
Terraform file is used for setting up our networking resources such as Virtual Private Cloud (VPC), Internet Gateway, Route Table, and Routes. 


Associated Tech:
AWS CLI for local windows system.
Terraform 


Prerequisites for local -
* Create new a new private GitHub repository in the GitHub organization you created, with name must be aws-infra.
* Creating a .gitignore file using the ready template while creating the repository. In my case I used the Terraform template
* Write the workflow in .github/workflows to be executed before merging the pull request to organization/main
* Set the required branch protections in organization/main to avoid merging of pull request if the PR fails

Build and Deploy instructions for AWS Networking Setup -
* Create Virtual Private Cloud (VPC)
* Create subnets in your VPC. You must create 3 public subnets and 3 private subnets, each in a different availability zone in the same region in the same VPC.
* Create an Internet Gateway resource and attach the Internet Gateway to the VPC.
* Create a public route table. Attach all public subnets created to the route table.
* Create a private route table. Attach all private subnets created to the route table.
* Create a public route in the public route table created above with the destination CIDR block 0.0.0.0/0 and the internet gateway created above as the target.


Steps to be implemented --
* Creation of networking resources using the terraform apply command
* Create multiple VPCs (and resources) without any conflicts in the same AWS account & same region
* Create other VPCs (and resources) without any conflicts in different AWS regions
* Cleanup of networking resources using the terraform destroy command

### Important Terraform commands
1. terraform fmt
2. terraform init
3. terraform plan -var-file="fileName.tfvars"
4. terraform apply
5. terraform destroy