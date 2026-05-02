# Verify SSM parameters exist and are readable
aws ssm get-parameter \
  --name "/terraform/db_username" \
  --with-decryption \
  --query "Parameter.Value" \
  --output text \
  --profile lab-sso --region us-east-2

aws ssm get-parameter \
  --name "/terraform/db_password" \
  --with-decryption \
  --query "Parameter.Value" \
  --output text \
  --profile lab-sso --region us-east-2
