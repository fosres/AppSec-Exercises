function lab-snapshot
	echo "Your running instances:"
	aws ec2 describe-instances \
		--filters "Name=instance-state-name,Values=running" \
		--query "Reservations[*].Instances[*].[InstanceId,State.Name]" \
		--output table \
		--profile lab-sso

	read --prompt-str "Enter Instance ID to snapshot (i-...): " instance_id

	if test -z "$instance_id"
		echo "ERROR: No Instance ID entered. Cancelled."
		return 1
	end

	read --prompt-str "Enter a name for this snapshot: " snapshot_name

	if test -z "$snapshot_name"
		echo "ERROR: No snapshot name entered. Cancelled."
		return 1
	end

	# Get the root volume device name from the running instance
	set device_name (aws ec2 describe-instances \
		--instance-ids $instance_id \
		--query "Reservations[0].Instances[0].RootDeviceName" \
		--output text \
		--profile lab-sso)

	set today (date +%Y-%m-%d)
	echo "Creating encrypted snapshot of $instance_id..."

	set ami_id (aws ec2 create-image \
		--instance-id $instance_id \
		--name "$snapshot_name-$today" \
		--description "Lab snapshot: $snapshot_name" \
		--no-reboot \
		--block-device-mappings "[{\"DeviceName\":\"$device_name\",\"Ebs\":{\"Encrypted\":true,\"DeleteOnTermination\":true}}]" \
		--profile lab-sso \
		--query "ImageId" \
		--output text)

	if test -z "$ami_id"
		echo "ERROR: Failed to create snapshot."
		return 1
	end

	echo "Snapshot created: $ami_id (encrypted)"
	echo "Waiting for snapshot to become available..."
	aws ec2 wait image-available \
		--image-ids $ami_id \
		--profile lab-sso

	echo "Snapshot is ready: $ami_id"
	echo "Use this ID with lab-restore to launch from this state."
end
