function lab-start
    aws ec2 start-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Starting... wait 60 seconds"
end
