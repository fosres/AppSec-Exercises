function lab-snapshot-delete
	echo "Your saved AMIs:"
	aws ec2 describe-images \
		--owners self \
		--query "Images[*].[ImageId,Name,CreationDate]" \
		--output table \
		--profile lab-sso

	read --prompt-str "Enter AMI ID to delete (ami-...): " ami_id

	if test -z "$ami_id"
		echo "ERROR: No AMI ID entered. Cancelled."
		return 1
	end

	# Get the snapshot ID backing this AMI before deregistering
	set snapshot_id (aws ec2 describe-images \
		--image-ids $ami_id \
		--query "Images[0].BlockDeviceMappings[0].Ebs.SnapshotId" \
		--output text \
		--profile lab-sso)

	read --prompt-str "Delete $ami_id ($snapshot_id)? Type YES to confirm: " confirm

	if test "$confirm" != "YES"
		echo "Cancelled."
		return 0
	end

	# Step 1: Deregister the AMI
	aws ec2 deregister-image \
		--image-id $ami_id \
		--profile lab-sso

	echo "AMI deregistered: $ami_id"

	# Step 2: Delete the underlying EBS snapshot
	aws ec2 delete-snapshot \
		--snapshot-id $snapshot_id \
		--profile lab-sso

	echo "Snapshot deleted: $snapshot_id"
	echo "Done. Storage charges for this snapshot will stop within the hour."
end
