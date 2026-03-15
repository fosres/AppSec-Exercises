function lab-status
    aws ec2 describe-instances --instance-ids $INSTANCE_ID \
        --profile lab-sso \
        --query "Reservations[0].Instances[0].State.Name" \
        --output text
end
