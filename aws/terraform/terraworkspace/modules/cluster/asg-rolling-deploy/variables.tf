variable "cluster_name" {
	description = "The name to use for all the cluster resources"
	type        = string
}

variable "ami" {
	description = "The AMI to run in the cluster"
	type        = string
	default     = null
}

variable "instance_type" {
	description = "The type of EC2 instances to run (e.g. t3.micro)"
	type        = string
}

variable "min_size" {
	description = "The minimum number of EC2 instances in the ASG"
	type        = number
}

variable "max_size" {
	description = "The maximum number of EC2 instances in the ASG"
	type        = number
}

variable "enable_autoscaling" {
	description = "If set to true, enable auto scaling"
	type        = bool
}

variable "custom_tags" {
	description = "Custom tags to set on the instances in the ASG"
	type        = map(string)
	default     = {}
}

variable "server_port" {
	description = "The port the server will use for HTTP requests"
	type        = number
	default     = 8080
}

variable "subnet_ids" {
	description = "The subnet IDs to deploy to"
	type        = list(string)
}

variable "target_group_arns" {
	description = "The ARNs of ELB target groups in which to register instances"
	type        = list(string)
	default     = []
}

variable "health_check_type" {
	description = "The type of health check to perform. Must be one of: EC2, ELB."
	type        = string
	default     = "EC2"
}

variable "user_data" {
	description = "The User Data script to run in each instance at boot"
	type        = string
	default     = null
}
