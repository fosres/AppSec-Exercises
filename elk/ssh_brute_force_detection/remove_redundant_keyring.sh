# Remove the conflicting source we just added
sudo rm -f /etc/apt/keyrings/docker.gpg
sudo rm -f /etc/apt/sources.list.d/docker.list

# Verify only the original remains
ls /etc/apt/keyrings/docker*
cat /etc/apt/sources.list.d/docker.list 2>/dev/null || \
  ls /etc/apt/sources.list.d/ | grep docker
