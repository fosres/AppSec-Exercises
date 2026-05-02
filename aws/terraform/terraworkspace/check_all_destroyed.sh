# EC2 instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[*].Instances[*].[InstanceId,InstanceType,Tags[?Key=='Name'].Value|[0]]" \
  --output table --region us-east-2 --profile lab-sso

# Load balancers
aws elbv2 describe-load-balancers \
  --query "LoadBalancers[*].[LoadBalancerName,State.Code]" \
  --output table --region us-east-2 --profile lab-sso

# RDS instances
aws rds describe-db-instances \
  --query "DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus,DBInstanceClass]" \
  --output table --region us-east-2 --profile lab-sso

# DynamoDB tables
aws dynamodb list-tables \
  --output table --region us-east-2 --profile lab-sso

# S3 buckets (global, no region flag)
aws s3 ls --profile lab-sso

# Auto scaling groups
aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[*].[AutoScalingGroupName,DesiredCapacity]" \
  --output table --region us-east-2 --profile lab-sso

# Target groups
aws elbv2 describe-target-groups \
  --query "TargetGroups[*].[TargetGroupName]" \
  --output table --region us-east-2 --profile lab-sso
