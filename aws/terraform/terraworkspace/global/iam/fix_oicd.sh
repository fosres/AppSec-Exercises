cd ~/Personal/git/AppSec-Exercises/aws/terraform/terraworkspace/global/iam

# Import OIDC provider
terragrunt import aws_iam_openid_connect_provider.github_actions \
  arn:aws:iam::510537392097:oidc-provider/token.actions.githubusercontent.com

# Import GitHub Actions role
terragrunt import aws_iam_role.github_actions github-actions-terraform

# Import neo user
terragrunt import aws_iam_user.neo neo

# Import CloudWatch policies
terragrunt import aws_iam_policy.cloudwatch_read_only \
  arn:aws:iam::510537392097:policy/cloudwatch-read-only

terragrunt import aws_iam_policy.cloudwatch_full_access \
  arn:aws:iam::510537392097:policy/cloudwatch-full-access
