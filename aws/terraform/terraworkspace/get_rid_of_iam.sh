# Detach PowerUserAccess from GitHub Actions role
aws iam detach-role-policy \
  --role-name github-actions-terraform \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess \
  --profile lab-sso

# Delete GitHub Actions role
aws iam delete-role \
  --role-name github-actions-terraform \
  --profile lab-sso

# Delete OIDC provider
aws iam delete-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::510537392097:oidc-provider/token.actions.githubusercontent.com \
  --profile lab-sso

# Detach CloudWatch policy from neo
aws iam detach-user-policy \
  --user-name neo \
  --policy-arn arn:aws:iam::510537392097:policy/cloudwatch-read-only \
  --profile lab-sso

# Delete neo user
aws iam delete-user \
  --user-name neo \
  --profile lab-sso

# Delete CloudWatch policies
aws iam delete-policy \
  --policy-arn arn:aws:iam::510537392097:policy/cloudwatch-read-only \
  --profile lab-sso

aws iam delete-policy \
  --policy-arn arn:aws:iam::510537392097:policy/cloudwatch-full-access \
  --profile lab-sso
