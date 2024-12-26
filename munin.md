# Munin How-To Guide

I have been installing and managing Linux systems for over 20 years, and Munin remains one of the best free solutions for gaining a comprehensive view of server and system behavior to effectively track and resolve issues. It offers a wide range of plugins for popular databases and services, while also providing a straightforward framework for creating custom monitoring scripts in languages like Python and TypeScript. This guide will walk you through setting up Munin to monitor system performance, including configuration with an Nginx web server on the main server and a node server.

## Main Server Setup
1. Install Munin:

```bash
sudo apt update
sudo apt install munin
```


2. Edit Munin Configuration:
Open the Munin configuration file:

```bash

sudo nano /etc/munin/munin.conf
```

Add your node configuration:

```conf

[node0]
       address 10.1.1.2
```


3. Set Up Nginx:

Install Nginx if not already installed:

```bash

sudo apt install nginx
```

Configure Nginx for Munin by creating a new configuration file:

```bash

sudo nano /etc/nginx/sites-available/munin
```

Add the following content:

```conf

server {
    listen 80;
    server_name munin.example.com;

    location /munin/ {
        alias /var/cache/munin/www/;
        autoindex on;
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```


4. Enable the Nginx Configuration:

```bash

sudo ln -s /etc/nginx/sites-available/munin /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```


5. Set up Basic Authentication (Optional):
   
Install the htpasswd utility:

```bash

sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

6. Verify Setup:
Visit http://10.1.1.1/munin/ in your browser. 

## Node Server Setup
1. Install Munin Node:

```bash

sudo apt update
sudo apt install munin-node
```


2. Configure Munin Node:
   
Edit the Munin node configuration:

```bash

sudo nano /etc/munin/munin-node.conf
```

Allow connections from the main server:

```conf

allow ^10\.1\.1\.1$
```

3. Install Additional Plugins (Optional):

```bash

sudo apt install munin-plugins-extra
```

4. Restart the Munin Node Service:

```bash

sudo systemctl restart munin-node.service
```

Monitor Your Own System

You can monitor custom metrics by writing your own plugin scripts. For example:

Example Custom Plugin Script:

```bash

#!/bin/bash
# /usr/share/munin/plugins/example
# Munin plugin to monitor disk usage on /

case $1 in
    config)
        echo "graph_title Disk Usage on /"
        echo "graph_vlabel Bytes"
        echo "graph_category disk"
        echo "usage.label Used Space"
        exit 0
        ;;
esac

df --output=used / | tail -1
```

**Installation:**
	1.	Save the script in the /usr/share/munin/plugins/ directory.
	2.	Make it executable:

```bash

sudo chmod +x /usr/share/munin/plugins/example
```

3. Create a symbolic link in /etc/munin/plugins/:
```bash

sudo ln -s /usr/share/munin/plugins/example /etc/munin/plugins/example
```

4. Restart the Munin Node service:

```bash

sudo systemctl restart munin-node.service
```

Testing and Debugging

Test the node setup by running:

```bash

munin-run example
```

You should see the output of the custom script.

Ensure all configurations are correctly applied and logs are monitored for errors:

```bash

sudo tail -f /var/log/munin/munin-update.log
sudo tail -f /var/log/munin/munin-node.log
```

Now, your Munin server and node should be up and running, monitoring your systems effectively!

Let me know if you need any help x.com/juvinski

