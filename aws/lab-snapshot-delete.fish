function lab-snapshot-delete
	echo "Your saved AMIs:"
	aws ec2 describe-images \
		--owners self \
		--query "Images[*].[ImageId,Name,CreationDate]" \
		--output table \
		--profile lab-sso

	echo ""
	echo "Enter AMI IDs to delete, one per line."
	echo "Press Ctrl+D when done."
	echo ""

	set ami_ids

	while read --prompt-str "" ami_id
		set --append ami_ids $ami_id
	end

	if test (count $ami_ids) -eq 0
		echo "No AMI IDs entered. Cancelled."
		return 1
	end

	echo ""
	echo "The following snapshots will be permanently deleted:"
	for ami_id in $ami_ids
		echo "  - $ami_id"
	end
	echo ""

	read --prompt-str "Type YES to confirm deletion of all "(count $ami_ids)" snapshot(s): " confirm

	if test "$confirm" != "YES"
		echo "Cancelled."
		return 0
	end

	for ami_id in $ami_ids
		echo ""
		echo "Processing $ami_id..."

		set snapshot_id (aws ec2 describe-images \
			--image-ids $ami_id \
			--query "Images[0].BlockDeviceMappings[0].Ebs.SnapshotId" \
			--output text \
			--profile lab-sso)

		if test -z "$snapshot_id" -o "$snapshot_id" = "None"
			echo "WARNING: Could not find snapshot for $ami_id — skipping."
			continue
		end

		aws ec2 deregister-image \
			--image-id $ami_id \
			--profile lab-sso
		echo "AMI deregistered: $ami_id"

		aws ec2 delete-snapshot \
			--snapshot-id $snapshot_id \
			--profile lab-sso
		echo "Snapshot deleted: $snapshot_id"
	end

	echo ""
	echo "Done. Storage charges for deleted snapshots will stop within the hour."
end
