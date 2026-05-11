# Unlock stage mysql
aws s3api delete-object \
  --bucket fosres-terraform-state \
  --key "stage/data-stores/mysql/terraform.tfstate.tflock" \
  --profile lab-sso

# Unlock prod mysql
aws s3api delete-object \
  --bucket fosres-terraform-state \
  --key "prod/data-stores/mysql/terraform.tfstate.tflock" \
  --profile lab-sso
