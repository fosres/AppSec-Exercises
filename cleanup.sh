cd ~/Personal/git/AppSec-Exercises/aws/terraform/terraworkspace

# One-time setup scripts — already done, never needed again
rm fix_account_id.sh
rm create_user_data.sh
rm test.sh

# Debugging scripts — stale paths, no longer useful
rm check_debug.sh
rm destroy_rest.sh

# Duplicate of destroy_leftovers.sh
rm killall.sh

# Debugging scripts for old RDS instances with hardcoded identifiers
rm delete_rest.sh
rm destroy_autoscale.sh

# IAM cleanup — duplicate of cleanup.sh
rm get_rid_of_iam.sh

# SSM scripts — we use Secrets Manager not SSM
rm check_db_secrets_in_ssm_exists.sh
rm delete_database_secrets_aws_ssm.sh

# One-time debugging script inside global/iam
rm global/iam/fix_oicd.sh

# Stale root-level lock file — shouldn't exist at workspace root
rm .terraform.lock.hcl

# Old pre-refactor module — superseded by hello-world-app
rm -rf modules/services/webserver-cluster/
