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
	source = "."

	extra_arguments "db_credentials" {
		commands = ["apply", "plan", "destroy", "validate"]
		env_vars = {
			TF_VAR_db_username = get_env("TF_VAR_db_username", "placeholder")
			TF_VAR_db_password = get_env("TF_VAR_db_password", "placeholder")
		}
	}
}

dependency "s3" {
	config_path = "../../../global/s3"
	skip_outputs = true

	mock_outputs = {
		s3_bucket_arn       = "arn:aws:s3:::mock-bucket"
		dynamodb_table_name = "mock-table"
	}
	mock_outputs_allowed_terraform_commands = ["plan", "validate", "destroy"]
}
