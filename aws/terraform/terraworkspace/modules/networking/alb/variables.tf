variable "alb_name" {
	description = "The name to use for this ALB"
	type        = string
}

variable "subnets" {
	description = "The subnet IDs to deploy the ALB into"
	type        = list(string)
}
