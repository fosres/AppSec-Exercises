function lab-stop
    aws ec2 stop-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Stopping..."
end
