aws secretsmanager get-secret-value \
                                            --secret-id "terraform/db_credentials" \
                                            --region us-east-2 \
                                            --profile lab-sso
