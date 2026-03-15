function lab-create
    echo "Launching new suricata-ids-lab instance..."
    set new_id (aws ec2 run-instances \
        --launch-template LaunchTemplateName=suricata-lab-template \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=suricata-ids-lab}]" \
        --profile lab-sso \
        --query "Instances[0].InstanceId" \
        --output text)

    if test -z "$new_id"
        echo "ERROR: Failed to launch instance."
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
    echo "Waiting 3 minutes for SSM Agent to initialize..."
    sleep 180

    echo "Ready. Run lab-connect to start your session."
end
