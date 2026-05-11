locals {
	http_port    = 80
	any_port     = 0
	any_protocol = "-1"
	tcp_protocol = "tcp"
	all_ips      = ["0.0.0.0/0"]
}

data "aws_vpc" "default" {
	default = true
}

data "aws_ami" "debian" {
	most_recent = true
	owners      = ["136693071363"]

	filter {
		name   = "name"
		values = ["debian-12-amd64-*"]
	}

	filter {
		name   = "virtualization-type"
		values = ["hvm"]
	}
}

data "aws_subnets" "default" {
	filter {
		name   = "vpc-id"
		values = [data.aws_vpc.default.id]
	}
}

data "terraform_remote_state" "db" {
	backend = "s3"

	config = {
		bucket  = var.db_remote_state_bucket
		key     = var.db_remote_state_key
		region  = "us-east-2"
	}
}

resource "aws_security_group" "instance" {
	name        = "${var.cluster_name}-instance"
	description = "Allow inbound HTTP on port ${var.server_port} and all outbound traffic"

	ingress {

		# aws_security_group.instance ingress
		from_port   = var.server_port
		to_port     = var.server_port
		protocol    = local.tcp_protocol
		cidr_blocks = local.all_ips
		description = "Allow inbound HTTP on port ${var.server_port}"
	}

	egress {
		# aws_security_group.instance egress
		from_port   = local.any_port
		to_port     = local.any_port
		protocol    = local.any_protocol
		cidr_blocks = local.all_ips
		description = "Allow all outbound traffic"
	}
}

resource "aws_launch_template" "example" {
	name_prefix   = "${var.cluster_name}-"
	image_id      = data.aws_ami.debian.id
	instance_type = "t3.micro"

	vpc_security_group_ids = [aws_security_group.instance.id]

	user_data = base64encode(templatefile("${path.module}/user-data.sh", {
		server_port = var.server_port
		db_address  = data.terraform_remote_state.db.outputs.address
		db_port     = data.terraform_remote_state.db.outputs.port
		server_text = var.server_text
	}))

	metadata_options {
		http_endpoint = "enabled"
		http_tokens   = "required"
	}

	lifecycle {
		create_before_destroy = true
	}
}

resource "aws_autoscaling_group" "example" {
	name = "${var.cluster_name}-${aws_launch_template.example.id}"

	launch_template {
		id      = aws_launch_template.example.id
		version = "$Latest"
	}

	vpc_zone_identifier = data.aws_subnets.default.ids
	target_group_arns   = [aws_lb_target_group.asg.arn]
	health_check_type   = "ELB"

	min_size         = var.min_size
	max_size         = var.max_size
	min_elb_capacity = var.min_size

	lifecycle {
		create_before_destroy = true
	}

	tag {
		key                 = "Name"
		value               = var.cluster_name
		propagate_at_launch = true
	}

	dynamic "tag" {
		for_each = {
			for key, value in var.custom_tags :
			key => upper(value)
			if key != "Name"
		}

		content {
			key                 = tag.key
			value               = tag.value
			propagate_at_launch = true
		}
	}
}

resource "aws_security_group" "alb" {
	name        = "${var.cluster_name}-alb-sg"
	description = "Allow inbound HTTP on port 80 and all outbound traffic"

	ingress {
		# aws_security_group.alb ingress
		from_port   = local.http_port
		to_port     = local.http_port
		protocol    = local.tcp_protocol
		cidr_blocks = local.all_ips
		description = "Allow inbound HTTP on port 80"
	}

	egress {

		# aws_security_group.alb egress
		from_port   = local.any_port
		to_port     = local.any_port
		protocol    = local.any_protocol
		cidr_blocks = local.all_ips
		description = "Allow all outbound traffic"
	}
}

#checkov:skip=CKV_AWS_91:ALB access logging not required for tutorial
#checkov:skip=CKV_AWS_260:ALB must accept HTTP on port 80 for this tutorial
resource "aws_lb" "example" {
	name                       = "${var.cluster_name}-alb"
	load_balancer_type         = "application"
	subnets                    = data.aws_subnets.default.ids
	security_groups            = [aws_security_group.alb.id]
	drop_invalid_header_fields = true
}

resource "aws_lb_listener" "http" {
	load_balancer_arn = aws_lb.example.arn
	port 		= local.http_port
	protocol	= "HTTP"

	default_action {
		type = "fixed-response"

		fixed_response {
			content_type = "text/plain"
			message_body = "404: page not found"
			status_code  = 404
		}
	}
}

resource "aws_lb_target_group" "asg" {
	name     = "${var.cluster_name}-asg"
	port     = var.server_port
	protocol = "HTTP"
	vpc_id   = data.aws_vpc.default.id

	health_check {
		path                = "/"
		protocol            = "HTTP"
		matcher             = "200"
		interval            = 15
		timeout             = 3
		healthy_threshold   = 2
		unhealthy_threshold = 2
	}
}

resource "aws_lb_listener_rule" "asg" {
	listener_arn = aws_lb_listener.http.arn
	priority     = 100

	condition {
		path_pattern {
			values = ["*"]
		}
	}

	action {
		type             = "forward"
		target_group_arn = aws_lb_target_group.asg.arn
	}
}

resource "aws_autoscaling_schedule" "scale_out_during_business_hours" {
  count = var.enable_autoscaling ? 1 : 0

  scheduled_action_name  = "${var.cluster_name}-scale-out-during-business-hours"
  min_size               = 2
  max_size               = 10
  desired_capacity       = 10
  recurrence             = "0 9 * * *"
  autoscaling_group_name = aws_autoscaling_group.example.name
}

resource "aws_autoscaling_schedule" "scale_in_at_night" {
  count = var.enable_autoscaling ? 1 : 0

  scheduled_action_name  = "${var.cluster_name}-scale-in-at-night"
  min_size               = 2
  max_size               = 10
  desired_capacity       = 2
  recurrence             = "0 17 * * *"
  autoscaling_group_name = aws_autoscaling_group.example.name
}
