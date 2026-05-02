# Check locals block exists
head -10 ~/Personal/terraform/terraworkspace/modules/services/webserver-cluster/main.tf

# Check min_size and max_size exist
grep -E "min_size|max_size" ~/Personal/terraform/terraworkspace/modules/services/webserver-cluster/variables.tf
