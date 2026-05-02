cat ~/Personal/terraform/terraworkspace/stage/data-stores/mysql/.terragrunt-cache/oi-NyFAEJPhqk0KElwxs1Txrejo/F6bAydnneXCTm_2QSMNt8dPhCnQ/variables.tf

find ~/Personal/terraform/terraworkspace/stage/data-stores/mysql \
  -name "*.tfvars" -o -name "*.auto.tfvars" 2>/dev/null

cd ~/Personal/terraform/terraworkspace/stage/data-stores/mysql/.terragrunt-cache/oi-NyFAEJPhqk0KElwxs1Txrejo/F6bAydnneXCTm_2QSMNt8dPhCnQ

terraform plan \
  -var="db_username=admin" \
  -var="db_password=SecurePass123!" \
  -no-color 2>&1 | grep username
