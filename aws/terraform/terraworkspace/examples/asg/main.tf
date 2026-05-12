provider "aws" {
	region = "us-east-2"
}

data "aws_vpc" "default" {
	default = true
}

data "aws_subnets" "default" {
	filter {
		name   = "vpc-id"
		values = [data.aws_vpc.default.id]
	}
}

module "asg" {
	source = "../../modules/cluster/asg-rolling-deploy"

	cluster_name  = var.cluster_name
	instance_type = "t3.micro"

	min_size           = 1
	max_size           = 1
	enable_autoscaling = false

	subnet_ids        = data.aws_subnets.default.ids
	target_group_arns = []
	health_check_type = "EC2"

	db_address  = "mock-db-address"
	db_port     = 3306
	server_port = 8080
	server_text = "Hello, World"

	user_data = templatefile("${path.module}/user-data.sh", {
		server_port = 8080
		db_address  = "mock-db-address"
		db_port     = 3306
		server_text = "Hello, World"
	})
}
