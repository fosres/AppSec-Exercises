# Delete all versioned objects
aws s3api delete-objects \
  --bucket fosres-terraform-state \
  --delete "$(aws s3api list-object-versions \
    --bucket fosres-terraform-state \
    --query '{Objects: Versions[].{Key: Key, VersionId: VersionId}}' \
    --output json \
    --profile lab-sso)" \
  --profile lab-sso 2>/dev/null

# Delete all delete markers
aws s3api delete-objects \
  --bucket fosres-terraform-state \
  --delete "$(aws s3api list-object-versions \
    --bucket fosres-terraform-state \
    --query '{Objects: DeleteMarkers[].{Key: Key, VersionId: VersionId}}' \
    --output json \
    --profile lab-sso)" \
  --profile lab-sso 2>/dev/null

# Now delete the empty bucket
aws s3 rb s3://fosres-terraform-state --profile lab-sso
