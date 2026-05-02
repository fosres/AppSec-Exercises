#!/bin/bash

cat > /home/admin/index.html <<EOF
<h1>${server_text}</h1>
<p>DB address: ${db_address}</p>
<p>DB port: ${db_port}</p>
EOF

cd /home/admin
nohup python3 -m http.server ${server_port} &
