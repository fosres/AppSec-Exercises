cat > ~/Personal/terraform/terraworkspace/modules/services/webserver-cluster/user-data.sh << 'EOF'
#!/bin/bash

cat > /home/admin/index.html <<HTML
<h1>Hello, World</h1>
<p>DB address: ${db_address}</p>
<p>DB port: ${db_port}</p>
HTML

cd /home/admin
nohup python3 -m http.server ${server_port} &
EOF

chmod +x ~/Personal/terraform/terraworkspace/modules/services/webserver-cluster/user-data.sh
