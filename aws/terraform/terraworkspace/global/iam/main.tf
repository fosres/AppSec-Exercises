# Get current AWS account ID
data "aws_caller_identity" "current" {}

# GitHub Actions OIDC Provider — one-time setup per AWS account
resource "aws_iam_openid_connect_provider" "github_actions" {
	url             = "https://token.actions.githubusercontent.com"
	client_id_list  = ["sts.amazonaws.com"]
	thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# IAM Role for GitHub Actions
resource "aws_iam_role" "github_actions" {
	name = "github-actions-terraform"

	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [{
			Effect = "Allow"
			Principal = {
				Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
			}
			Action = "sts:AssumeRoleWithWebIdentity"
			Condition = {
				StringLike = {
					"token.actions.githubusercontent.com:sub" = "repo:fosres/SecEng-Exercises:*"
				}
			}
		}]
	})
}

# Attach PowerUserAccess to allow Terraform to manage AWS resources
#checkov:skip=CKV_AWS_356:PowerUserAccess is a bootstrap role for GitHub Actions CI/CD — scope will be tightened in production
#checkov:skip=CKV_AWS_111:PowerUserAccess is a bootstrap role for GitHub Actions CI/CD — scope will be tightened in production
resource "aws_iam_role_policy_attachment" "github_actions_terraform" {
	role       = aws_iam_role.github_actions.name
	policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

#checkov:skip=CKV_AWS_273:IAM user neo is a tutorial resource — SSO used for real access
resource "aws_iam_user" "neo" {
	name = "neo"
}

resource "aws_iam_policy" "cloudwatch_read_only" {
	name   = "cloudwatch-read-only"
	policy = data.aws_iam_policy_document.cloudwatch_read_only.json
}

data "aws_iam_policy_document" "cloudwatch_read_only" {
	statement {
		effect  = "Allow"
		actions = [
			"cloudwatch:Describe*",
			"cloudwatch:Get*",
			"cloudwatch:List*"
		]
		resources = ["*"]
	}
}

resource "aws_iam_policy" "cloudwatch_full_access" {
	name   = "cloudwatch-full-access"
	policy = data.aws_iam_policy_document.cloudwatch_full_access.json
}

data "aws_iam_policy_document" "cloudwatch_full_access" {
	statement {
		effect    = "Allow"
		actions   = ["cloudwatch:*"]
		resources = ["*"]
	}
}

#checkov:skip=CKV_AWS_40:Direct user policy attachment used for tutorial — groups not required
resource "aws_iam_user_policy_attachment" "neo_cloudwatch_full_access" {
	count      = var.give_neo_cloudwatch_full_access ? 1 : 0
	user       = aws_iam_user.neo.name
	policy_arn = aws_iam_policy.cloudwatch_full_access.arn
}

#checkov:skip=CKV_AWS_40:Direct user policy attachment used for tutorial — groups not required
resource "aws_iam_user_policy_attachment" "neo_cloudwatch_read_only" {
	count      = var.give_neo_cloudwatch_full_access ? 0 : 1
	user       = aws_iam_user.neo.name
	policy_arn = aws_iam_policy.cloudwatch_read_only.arn
}


#checkov:skip=CKV_AWS_356:IAM read-only inline policy required for GitHub Actions to manage global/iam resources
#checkov:skip=CKV_AWS_111:IAM read-only inline policy required for GitHub Actions to manage global/iam resources
resource "aws_iam_role_policy" "github_actions_iam_read" {
	name = "github-actions-iam-read"
	role = aws_iam_role.github_actions.name

	policy = jsonencode({
		Version = "2012-10-17"
		Statement = [{
			Effect = "Allow"
			Action = [
				"iam:GetRole",
				"iam:GetRolePolicy",
				"iam:GetUser",
				"iam:GetPolicy",
				"iam:GetPolicyVersion",
				"iam:GetOpenIDConnectProvider",
				"iam:ListAttachedRolePolicies",
				"iam:ListAttachedUserPolicies",
				"iam:ListRolePolicies",
				"iam:ListPolicyVersions",
				"iam:ListEntitiesForPolicy"
			]
			Resource = "*"
		}]
	})
}
