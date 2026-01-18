#!/usr/bin/bash

# Step 1: Create database
createdb -h localhost -U postgres auth_db

# Step 2: Load SQL file
psql -h localhost -U postgres -d auth_db -f users_postgres.sql

# Step 3: Verify it worked
psql -h localhost -U postgres -d auth_db -c "SELECT username, allowed_files FROM users;"
