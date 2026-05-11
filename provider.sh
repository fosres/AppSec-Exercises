cat > ~/Personal/git/AppSec-Exercises/aws/terraform/terraworkspace/prod/services/webserver-cluster/provider.tf << 'EOF'
provider "aws" {
  region = "us-east-2"
}
EOF

cat > ~/Personal/git/AppSec-Exercises/aws/terraform/terraworkspace/stage/services/webserver-cluster/provider.tf << 'EOF'
provider "aws" {
  region = "us-east-2"
}
EOF
