# Empty the S3 bucket first
aws s3api delete-objects \
  --bucket fosres-terraform-state \
  --delete "$(aws s3api list-object-versions \
    --bucket fosres-terraform-state \
    --query '{Objects: Versions[].{Key: Key, VersionId: VersionId}}' \
    --output json \
    --profile lab-sso)" \
  --profile lab-sso 2>/dev/null

aws s3api delete-objects \
  --bucket fosres-terraform-state \
  --delete "$(aws s3api list-object-versions \
    --bucket fosres-terraform-state \
    --query '{Objects: DeleteMarkers[].{Key: Key, VersionId: VersionId}}' \
    --output json \
    --profile lab-sso)" \
  --profile lab-sso 2>/dev/null

# Delete the bucket
aws s3 rb s3://fosres-terraform-state \
  --force --profile lab-sso

# Delete the DynamoDB table
aws dynamodb delete-table \
  --table-name terraform-up-and-running-locks \
  --region us-east-2 --profile lab-sso
