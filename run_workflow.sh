# Touch a file to trigger the path filter
echo "# Terraform Up and Running Ch. 2-6" > \
  ~/Personal/git/AppSec-Exercises/aws/terraworkspace/README.md

cd ~/Personal/git/AppSec-Exercises
git add aws/terraworkspace/README.md
git commit -m "Trigger GitHub Actions pipeline — add terraworkspace README"
git push origin main
