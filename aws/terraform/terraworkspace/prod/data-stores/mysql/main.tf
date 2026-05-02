data "aws_secretsmanager_secret_version" "db_creds" {
	secret_id = "terraform/db_credentials"
}

locals {
	db_creds = jsondecode(
		data.aws_secretsmanager_secret_version.db_creds.secret_string
	)
}

resource "aws_db_instance" "example" {
	identifier_prefix          = "terraform-up-and-running"
	engine                     = "mysql"
	engine_version             = "8.0"
	allocated_storage          = 10
	instance_class             = "db.t3.micro"
	skip_final_snapshot        = true
	db_name                    = "example_database"
	storage_encrypted          = true
	auto_minor_version_upgrade = true
	copy_tags_to_snapshot      = true

	username = local.db_creds["username"]
	password = local.db_creds["password"]
}

