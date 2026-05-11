# Add a blank line comment at the top
sed -i '1s/^/# Terraform CI\/CD Pipeline\n/' \
  ~/Personal/git/AppSec-Exercises/.github/workflows/terraform.yml

cd ~/Personal/git/AppSec-Exercises
git add .github/workflows/terraform.yml
git commit -m "Fix: force GitHub to re-parse workflow file"
git push origin main
