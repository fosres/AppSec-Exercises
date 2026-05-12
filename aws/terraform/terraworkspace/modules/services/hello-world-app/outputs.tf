output "alb_dns_name" {
	value       = module.alb.alb_dns_name
	description = "The domain name of the load balancer"
}

output "alb_http_listener_arn" {
	value       = module.alb.alb_http_listener_arn
	description = "The ARN of the HTTP listener"
}

output "alb_security_group_id" {
	value       = module.alb.alb_security_group_id
	description = "The ALB Security Group ID"
}

output "asg_name" {
	value       = module.asg.asg_name
	description = "The name of the Auto Scaling Group"
}

output "instance_security_group_id" {
	value       = module.asg.instance_security_group_id
	description = "The ID of the EC2 Instance Security Group"
}
