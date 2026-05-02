module "webserver_cluster" {
	source                 = "../../../modules/services/webserver-cluster"
	cluster_name           = "webservers-prod"
	db_remote_state_bucket = "fosres-terraform-state"
	db_remote_state_key    = "prod/data-stores/mysql/terraform.tfstate"
	server_port            = 8080
	min_size               = 2
	max_size               = 10
	enable_autoscaling     = true
	custom_tags = {
		Owner     = "fosres"
		ManagedBy = "terraform"
	}
}
