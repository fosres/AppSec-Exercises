locals {
	any_port     = 0
	any_protocol = "-1"
	tcp_protocol = "tcp"
	all_ips      = ["0.0.0.0/0"]
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

resource "aws_security_group" "instance" {
	name        = "${var.cluster_name}-instance"
	description = "Allow inbound HTTP on port ${var.server_port} and all outbound traffic"

	ingress {
		from_port   = var.server_port
		to_port     = var.server_port
		protocol    = local.tcp_protocol
		cidr_blocks = local.all_ips
		description = "Allow inbound HTTP on port ${var.server_port}"
	}

	egress {
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
	instance_type = var.instance_type

	vpc_security_group_ids = [aws_security_group.instance.id]

	user_data = var.user_data != null ? base64encode(var.user_data) : null

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

	vpc_zone_identifier = var.subnet_ids
	target_group_arns   = var.target_group_arns
	health_check_type   = var.health_check_type

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
