

include "root" {
	path = find_in_parent_folders()
}

errors {
	retry "s3_backend_not_ready" {
		retryable_errors = [
			"(?s).*NoSuchBucket.*",
			"(?s).*Failed to get existing workspaces.*",
			"(?s).*error loading the remote state.*"
		]
		max_attempts       = 10
		sleep_interval_sec = 10
	}
}

terraform {
	source = "${get_parent_terragrunt_dir()}//stage/services/webserver-cluster"
}

dependency "s3" {
	config_path = "../../../global/s3"

	mock_outputs = {
		s3_bucket_arn       = "arn:aws:s3:::mock-bucket"
		dynamodb_table_name = "mock-table"
	}
	mock_outputs_allowed_terraform_commands = ["plan", "validate", "destroy"]
}

dependency "db" {
	config_path = "../../data-stores/mysql"

	mock_outputs = {
		address = "mock-db-address"
		port    = 3306
	}
	mock_outputs_allowed_terraform_commands = ["plan", "validate", "destroy"]
}
