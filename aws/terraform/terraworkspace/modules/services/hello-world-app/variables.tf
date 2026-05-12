variable "server_port" {
	description = "The port the server will use for HTTP requests"
	type        = number
	default     = 8080

}

variable "cluster_name" {
  description = "The name to use for all the cluster resources"
  type        = string
}

variable "db_remote_state_bucket" {
  description = "The name of the S3 bucket for the database's remote state"
  type        = string
}

variable "db_remote_state_key" {
  description = "The path for the database's remote state in S3"
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

variable "custom_tags" {
	description = "Custom tags to set on the instances in the ASG"
	type        = map(string)
	default     = {}
}

variable "enable_autoscaling" {
  description = "If set to true, enable auto scaling"
  type        = bool
}

variable "server_text" {
	description = "The text the web server should return"
	type        = string
	default     = "Hello, World"
}

variable "environment" {
  description = "The name of the environment we're deploying to"
  type        = string
}

variable "ami" {
	description = "The AMI to run in the cluster"
	type        = string
}

variable "instance_type" {
	description = "The type of EC2 instances to run (e.g. t3.micro)"
	type        = string
}
