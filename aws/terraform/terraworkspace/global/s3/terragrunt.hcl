include "root" {
	path = find_in_parent_folders()
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
