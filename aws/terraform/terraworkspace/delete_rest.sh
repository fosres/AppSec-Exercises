# Get exact instance identifiers
aws rds describe-db-instances \
  --query "DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus]" \
  --output table --region us-east-2 --profile lab-sso

# Delete both instances
aws rds delete-db-instance \
  --db-instance-identifier terraform-up-and-running20260429214116092000000001 \
  --skip-final-snapshot \
  --region us-east-2 --profile lab-sso

aws rds delete-db-instance \
  --db-instance-identifier terraform-up-and-running20260429214116256800000001 \
  --skip-final-snapshot \
  --region us-east-2 --profile lab-sso
