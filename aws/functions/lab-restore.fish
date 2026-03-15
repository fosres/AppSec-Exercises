function lab-restore
    # List available snapshots to help the user pick
    echo "Your saved AMIs:"
    aws ec2 describe-images \
        --owners self \
        --query "Images[*].[ImageId,Name,CreationDate]" \
        --output table \
        --profile lab-sso

    read --prompt-str "Enter AMI ID to restore from (ami-...): " ami_id

    if test -z "$ami_id"
        echo "ERROR: No AMI ID entered. Cancelled."
        return 1
    end

    # Look up security group ID automatically
    set sg_id (aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=suricata-lab-sg" \
        --query "SecurityGroups[0].GroupId" \
        --output text \
        --profile lab-sso)

    if test -z "$sg_id"
        echo "ERROR: Could not find security group suricata-lab-sg."
        return 1
    end

    echo "Launching from snapshot $ami_id..."
    set new_id (aws ec2 run-instances \
        --image-id $ami_id \
        --instance-type t2.micro \
        --iam-instance-profile Name=suricata-lab-ssm-role \
        --security-group-ids $sg_id \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=suricata-ids-lab}]" \
        --profile lab-sso \
        --query "Instances[0].InstanceId" \
        --output text)

    if test -z "$new_id"
        echo "ERROR: Failed to launch instance. Check AMI ID and try again."
        return 1
    end

    echo "Instance launched: $new_id"
    echo "Updating INSTANCE_ID..."
    set -U INSTANCE_ID $new_id

    echo "Waiting for instance to reach running state..."
    aws ec2 wait instance-running \
        --instance-ids $new_id \
        --profile lab-sso

    echo "Instance is running."
    echo "Waiting 60 seconds for SSM Agent to initialize..."
    sleep 60

    echo "Ready. Run lab-connect to start your session."
end
