include "root" {
	path = find_in_parent_folders()
}

generate "provider_override" {
	path      = "provider.tf"
	if_exists = "overwrite"
	contents  = <<EOF
provider "aws" {
  region = "us-east-2"
}
EOF
}

terraform {
	source = "."
}

inputs = {
	give_neo_cloudwatch_full_access = false
}

dependency "s3" {
	config_path = "../../global/s3"

	mock_outputs = {
		s3_bucket_arn       = "arn:aws:s3:::mock-bucket"
		dynamodb_table_name = "mock-table"
	}
	mock_outputs_allowed_terraform_commands = ["plan", "validate", "destroy"]
}
