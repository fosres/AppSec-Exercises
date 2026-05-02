ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account \
  --output text \
  --profile lab-sso)

sed -i "s/YOUR_ACCOUNT_ID/$ACCOUNT_ID/g" \
  ~/Personal/git/AppSec-Exercises/.github/workflows/terraform.yml

sed -i "s/YOUR_ACCOUNT_ID/$ACCOUNT_ID/g" \
  ~/Personal/git/AppSec-Exercises/.github/workflows/terraform_destroy.yml

# Verify
grep "role-to-assume" \
  ~/Personal/git/AppSec-Exercises/.github/workflows/terraform.yml
