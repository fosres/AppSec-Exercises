function lab-snapshot-list
	echo "Your saved AMIs:"
	aws ec2 describe-images \
		--owners self \
		--query "Images[*].[ImageId,Name,CreationDate]" \
		--output table \
		--profile lab-sso
end
