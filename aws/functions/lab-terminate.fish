function lab-terminate
    echo "WARNING: This will permanently delete the instance and all data on it."
    echo "Instance: $INSTANCE_ID"
    read --prompt-str "Type YES to confirm: " confirm
    if test "$confirm" = "YES"
        aws ec2 terminate-instances --instance-ids $INSTANCE_ID --profile lab-sso
        echo "Instance terminated. Use lab-create to launch a fresh one."
    else
        echo "Cancelled."
    end
end
