# terraworkspace/terragrunt.hcl

remote_state {
	backend = "s3"
	generate = {
		path      = "backend.tf"
		if_exists = "overwrite_terragrunt"
	}
	config = {
		bucket       = "fosres-terraform-state"
		key          = "${path_relative_to_include()}/terraform.tfstate"
		region       = "us-east-2"
		encrypt      = true
		use_lockfile = true
		profile      = "lab-sso"
	}
}

generate "provider" {
	if_exists = "overwrite_terragrunt"
	path      = "provider.tf"
	contents  = <<EOF
provider "aws" {
  region  = "us-east-2"
  profile = "lab-sso"
}
EOF
}

terraform {
	extra_arguments "upgrade" {
		commands  = ["init"]
		arguments = ["-upgrade"]
	}
}
