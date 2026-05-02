module "webserver_cluster" {
	source = "../../../modules/services/webserver-cluster"
	cluster_name           = "webservers-stage"
	db_remote_state_bucket = "fosres-terraform-state"
	db_remote_state_key    = "stage/data-stores/mysql/terraform.tfstate"
	server_port            = 8080
	min_size               = 2
	max_size               = 10
	enable_autoscaling = false
}

resource "aws_security_group_rule" "allow_testing_inbound" {
	type              = "ingress"
	security_group_id = module.webserver_cluster.alb_security_group_id

	from_port   = 12345
	to_port     = 12345
	protocol    = "tcp"
	cidr_blocks = ["0.0.0.0/0"]
}
