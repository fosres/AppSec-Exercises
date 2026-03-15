function lab-connect
    aws ssm start-session --target $INSTANCE_ID --profile lab-sso
end
