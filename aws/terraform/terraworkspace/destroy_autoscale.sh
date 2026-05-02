# Get the ASG name first
aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'webservers-prod')].AutoScalingGroupName" \
  --output text \
  --region us-east-2 --profile lab-sso

# Delete the orphaned schedule
aws autoscaling delete-scheduled-action \
  --auto-scaling-group-name <ASG_NAME_FROM_ABOVE> \
  --scheduled-action-name "webservers-prod-scale-in-at-night" \
  --region us-east-2 --profile lab-sso

# Also delete scale-out just in case
aws autoscaling delete-scheduled-action \
  --auto-scaling-group-name <ASG_NAME_FROM_ABOVE> \
  --scheduled-action-name "webservers-prod-scale-out-during-business-hours" \
  --region us-east-2 --profile lab-sso
