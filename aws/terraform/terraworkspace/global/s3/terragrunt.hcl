include "root" {
	path = find_in_parent_folders()
}

generate "provider_override" {
	path      = "provider.tf"
	if_exists = "overwrite"
	contents  = <<EOF
provider "aws" {
  region  = "us-east-2"
  profile = "lab-sso"
}
EOF
}

# global/s3 creates the state bucket itself so it cannot use
# remote state — it must store state locally
remote_state {
	backend  = "local"
	generate = {
		path      = "backend.tf"
		if_exists = "overwrite"
	}
	config = {
		path = "${get_parent_terragrunt_dir()}/global/s3/terraform.tfstate"
	}
}

terraform {
	source = "."
}
