# 1. Prod webserver
cd ~/Personal/terraform/terraworkspace/prod/services/webserver-cluster
terragrunt destroy

# 2. Stage webserver  
cd ~/Personal/terraform/terraworkspace/stage/services/webserver-cluster
terragrunt destroy

# 3. Prod mysql
cd ~/Personal/terraform/terraworkspace/prod/data-stores/mysql
terragrunt destroy

# 4. Stage mysql
cd ~/Personal/terraform/terraworkspace/stage/data-stores/mysql
terragrunt destroy

# 5. Global IAM
cd ~/Personal/terraform/terraworkspace/global/iam
terragrunt destroy

# 6. Global S3
cd ~/Personal/terraform/terraworkspace/global/s3
terragrunt destroy
