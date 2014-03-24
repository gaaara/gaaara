#!/bin/bash

  clear
 
    if [ $(id -u) -ne 0 ]
    then
       echo
       echo "This script must be run as root." 1>&2
       echo
       exit 1
    fi
 
    # demander nom et mot de passe
    read -p "Adding user now, please type your user name: " user
    read -s -p "Enter password: " pwd
    echo
 
    # ajout utilisateur
    useradd -m  -s /bin/bash "$user"
 
    # creation du mot de passe pour cet utilisateur
    echo "${user}:${pwd}" | chpasswd

 # gestionnaire de paquet
if [ "`dpkg --status aptitude | grep Status:`" == "Status: install ok installed" ]
then
        packetg="aptitude"
else
        packetg="apt-get"
fi


ip=$(ip addr | grep eth0 | grep inet | awk '{print $2}' | cut -d/ -f1)

##Log de l'instalation
exec 2>/home/$user/log

# Ajoute des dépots non-free
echo "#dépôt paquet propriétaire
deb http://ftp2.fr.debian.org/debian/ wheezy main non-free
deb-src http://ftp2.fr.debian.org/debian/ wheezy main non-free

# dépôt dotdeb php 5.5
deb http://packages.dotdeb.org wheezy-php55 all
deb-src http://packages.dotdeb.org wheezy-php55 all

# dépôt nginx
deb http://nginx.org/packages/debian/ wheezy nginx
deb-src http://nginx.org/packages/debian/ wheezy nginx" >> /etc/apt/sources.list

#Ajout des clée

##dotdeb
cd /tmp
wget http://www.dotdeb.org/dotdeb.gpg
apt-key add dotdeb.gpg

##nginx
cd /tmp
wget http://nginx.org/keys/nginx_signing.key
apt-key add nginx_signing.key

# Installation des paquets vitaux
$packetg update
$packetg safe-upgrade -y
$packetg install -y htop python build-essential pkg-config libcurl4-openssl-dev libsigc++-2.0-dev libncurses5-dev nginx vim nano screen subversion apache2-utils curl php5 php5-cli php5-fpm php5-curl php5-geoip git unzip unrar rar zip ffmpeg buildtorrent curl mediainfo


##Working directory##
mkdir work

if [ -z $workdir ]
then
        homedir="/work"
fi
###########################################################
##     Installation XMLRPC Libtorrent Rtorrent           ##
###########################################################

svn checkout http://svn.code.sf.net/p/xmlrpc-c/code/stable xmlrpc-c
cd xmlrpc-c
./configure --disable-cplusplus
make
make install
cd ..
rm -rv xmlrpc-c


#clone rtorrent et libtorrent
wget --no-check-certificate http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.2.tar.gz
tar -xf libtorrent-0.13.2.tar.gz

wget --no-check-certificate http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.2.tar.gz
tar -xzf rtorrent-0.9.2.tar.gz

# libtorrent compilation
cd libtorrent-0.13.2
./autogen.sh
./configure
make
make install

# rtorrent compilation
cd ../rtorrent-0.9.2
./autogen.sh
./configure --with-xmlrpc-c
make
make install
###########################################################
##              Fin Instalation                          ##
###########################################################

#Creation des dossier
mkdir /var/www
su $user -c 'mkdir -p ~/downloads ~/uploads ~/incomplete ~/rtorrent ~/rtorrent/session'

#Téléchargement + déplacement de rutorrent (web)
svn checkout http://rutorrent.googlecode.com/svn/trunk/rutorrent/
svn checkout http://rutorrent.googlecode.com/svn/trunk/plugins/
mv ./plugins/* ./rutorrent/plugins/
rm -R ./plugins
mv rutorrent/ /var/www

###########################################################
##              Instalation des Plugins                  ##
###########################################################

cd /var/www/rutorrent/plugins/

##Logoff
svn co http://rutorrent-logoff.googlecode.com/svn/trunk/ logoff

##tadd-labels
wget http://rutorrent-tadd-labels.googlecode.com/files/lbll-suite_0.8.1.tar.gz
tar zxfv lbll-suite_0.8.1.tar.gz
rm lbll-suite_0.8.1.tar.gz


##Filemanager
svn co http://svn.rutorrent.org/svn/filemanager/trunk/filemanager
sed -i "s#pathToExternals\['rar'\] = '';#pathToExternals\['rar'\] = '/usr/bin/rar';#" /var/www/rutorrent/plugins/filemanager/conf.php
sed -i "s#pathToExternals\['zip'\] = '';#pathToExternals\['zip'\] = '/usr/bin/zip';#" /var/www/rutorrent/plugins/filemanager/conf.php
sed -i "s#pathToExternals\['unzip'\] = '';#pathToExternals\['unzip'\] = '/usr/bin/unzip';#" /var/www/rutorrent/plugins/filemanager/conf.php
sed -i "s#pathToExternals\['tar'\] = '';#pathToExternals\['tar'\] = '/bin/tar';#" /var/www/rutorrent/plugins/filemanager/conf.php
sed -i "s#pathToExternals\['gzip'\] = '';#pathToExternals\['gzip'\] = '/bin/gzip';#" /var/www/rutorrent/plugins/filemanager/conf.php
sed -i "s#pathToExternals\['bzip2'\] = '';#pathToExternals\['bzip2'\] = '/bin/bzip2';#" /var/www/rutorrent/plugins/filemanager/conf.php

##FILEUPLOAD
svn co http://svn.rutorrent.org/svn/filemanager/trunk/fileupload
chmod 775 fileupload/scripts/upload
###dependance
##Plowshare
cd    /home
    git clone https://code.google.com/p/plowshare/ plowshare4
    cd plowshare4
    make install

#on met à jour les liens symboliques et les permissions
ldconfig
chown -R www-data:www-data /var/www/rutorrent

#Configuration du plugin create
sed -i "s#$useExternal = false;#$useExternal = 'buildtorrent';#" /var/www/rutorrent/plugins/create/conf.php
sed -i "s#$pathToCreatetorrent = '';#$pathToCreatetorrent = '/usr/bin/buildtorrent';#" /var/www/rutorrent/plugins/create/conf.php



###########################################################
##              Configuration de php-fpm                 ##
###########################################################

##php.ini

sed -i.bak "s/2m/10m/g;" /etc/php5/fpm/php.ini
sed -i.bak "s/expose_php = On/expose_php = Off/g;" /etc/php5/fpm/php.ini
sed -i.bak "s/date.timezone =/date.timezone = Europe/Paris/g;" /etc/php5/fpm/php.ini

service php5-fpm restart

###########################################################
##              Configuration serveur web                ##
###########################################################

mkdir /etc/nginx/passwd
mkdir /etc/nginx/ssl
touch /etc/nginx/passwd/rutorrent_passwd
chmod 640 /etc/nginx/passwd/rutorrent_passwd

rm /etc/nginx/nginx.conf

cat <<'EOF' > /etc/nginx/nginx.conf
user nginx;
worker_processes auto;

pid /var/run/nginx.pid;
events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log combined;
    error_log /var/log/nginx/error.log error;
    
    sendfile on;
    keepalive_timeout 20;
    keepalive_disable msie6;
    keepalive_requests 100;
    tcp_nopush on;
    tcp_nodelay off;
    server_tokens off;
    
    gzip on;
    gzip_buffers 16 8k;
    gzip_comp_level 5;
    gzip_disable "msie6";
    gzip_min_length 20;
    gzip_proxied any;
    gzip_types text/plain text/css application/json  application/x-javascript text/xml application/xml application/xml+rss  text/javascript;
    gzip_vary on;

    include /etc/nginx/sites-enabled/*.conf;
}
EOF




cat <<'EOF' > /etc/nginx/conf.d/php
location ~ \.php$ {
	fastcgi_index index.php;
	fastcgi_pass unix:/var/run/php5-fpm.sock;
	fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
	include /etc/nginx/fastcgi_params;
}
EOF

cat <<'EOF' > /etc/nginx/conf.d/cache
location ~* \.(jpg|jpeg|gif|css|png|js|woff|ttf|svg|eot)$ {
    expires 7d;
    access_log off;
}

location ~* \.(eot|ttf|woff|svg)$ {
    add_header Acccess-Control-Allow-Origin *;
}
EOF

mkdir /etc/nginx/sites-enabled
touch /etc/nginx/sites-enabled/rutorrent.conf

cat <<'EOF' > /etc/nginx/sites-enabled/rutorrent.conf
server {
    listen 80 default_server;
    listen 443 default_server ssl;
    server_name _;
    index index.html index.php;
    charset utf-8;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    access_log /var/log/nginx/rutorrent-access.log combined;
    error_log /var/log/nginx/rutorrent-error.log error;
    
    error_page 500 502 503 504 /50x.html;
    location = /50x.html { root /usr/share/nginx/html; }

    auth_basic "seedbox";
    auth_basic_user_file "/etc/nginx/passwd/rutorrent_passwd";
    
    location = /favicon.ico {
        access_log off;
        return 204;
    }
    
	
    ## début config rutorrent ##

    location ^~ /rutorrent {
	root /var/www;
	include /etc/nginx/conf.d/php;
	include /etc/nginx/conf.d/cache;

	location ~ /\.svn {
		deny all;
	}

	location ~ /\.ht {
		deny all;
	}
    }

    location ^~ /rutorrent/conf/ {
	deny all;
    }

    location ^~ /rutorrent/share/ {
	deny all;
    }
    
    ## fin config rutorrent ##

    ## Début config cakebox 2.8 ##

#    location ^~ /cakebox {
#	root /var/www/;
#	include /etc/nginx/conf.d/php;
#	include /etc/nginx/conf.d/cache;
#    }

#    location /cakebox/downloads {
#	root /var/www;
#	satisfy any;
#	allow all;
#    }

    ## fin config cakebox 2.8 ##

    ## début config seedbox manager ##

#    location ^~ / {
#	root /var/www/manager;
#	include /etc/nginx/conf.d/php;
#	include /etc/nginx/conf.d/cache;
#    }

#    location ^~ /conf/ {
#	root /var/www/manager;
#	deny all;
#    }

    ## fin config seedbox manager ##

}
EOF




mkdir /etc/nginx/ssl/
cd /etc/nginx/ssl/

###########################################################
##             SSL Configuration                         ##
###########################################################

#!/bin/bash
mkdir /etc/nginx/ssl
cd /etc/nginx/ssl

#Required
domain=$1
server.key=$domain
 
#Change to your company details
country=na
state=Na
locality=Na
organization=Jad
organizationalunit=IT
email=administrator@ratata.nu
 
#Optional
password=dummypassword
  
echo "Generating key request for $domain"
 
#Generate a key
openssl genrsa -des3 -passout pass:$password -out $domain.key 2048 -noout
 
#Remove passphrase from the key. Comment the line out to keep the passphrase
echo "Removing passphrase from key"
openssl rsa -in $domain.key -passin pass:$password -out $domain.key
 
#Create the request
echo "Creating CSR"
openssl req -new -key $domain.key -out $domain.csr -passin pass:$password \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

echo "---------------------------"
echo "-----Below is your CSR-----"
echo "---------------------------"
echo
cat $domain.csr
 
echo
echo "---------------------------"
echo "-----Below is your Key-----"
echo "---------------------------"
echo
cat $domain.key

service nginx restart
###########################################################
##             SSL Configuration    Fin                  ##
###########################################################
rm /etc/logrotate.d/nginx && touch /etc/logrotate.d/nginx
##Configuration de Logrotate pour nginx

cat <<'EOF' > /etc/logrotate.d/nginx
/var/log/nginx/*.log {
	daily
	missingok
	rotate 52
	compress
	delaycompress
	notifempty
	create 640 root
	sharedscripts
        postrotate
                [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
        endscript
}
EOF
#SSH config
sed -i.bak "s/Subsystem sftp/#Subsystem sftp/g;" /etc/ssh/sshd_config
sed -i.bak "s/UsePAM/#UsePAM/g;" /etc/php5/fpm/php.ini
sed -i.old -e "78i\Subsystem sftp internal-sftp" /etc/ssh/sshd_config
    
cat <<'EOF' >  /home/$user/.rtorrent.rc
execute = {sh,-c,rm -f /home/@user@/rtorrent/session/rpc.socket}
scgi_local = /home/@user@/rtorrent/session/rpc.socket
execute = {sh,-c,chmod 0666 /home/@user@/rtorrent/session/rpc.socket}
encoding_list = UTF-8
system.umask.set = 022
port_random = yes
check_hash = no
directory = /home/@user@/incomplete
session = /home/@user@/rtorrent/session
encryption = allow_incoming, try_outgoing, enable_retry
trackers.enable = 1
use_udp_trackers = yes
EOF
sed -i.bak "s/@user@/$user/g;" /home/$user/.rtorrent.rc

chown -R $user:$user /home/$user
chown root:$user /home/$user
chmod 755 /home/$user

###########################################################
##                    htpasswd                           ##
###########################################################
mkdir /etc/nginx/passwd
touch /etc/nginx/passwd/rutorrent_passwd
cd $workdir
wget http://trac.edgewall.org/export/10791/trunk/contrib/htpasswd.py
python htpasswd.py -b /etc/nginx/passwd/rutorrent_passwd $user ${pwd}
chown -c nginx:nginx /etc/nginx/passwd/*
service nginx restart
###########################################################
##                    htpasswd                           ##
###########################################################

## répertoire de configuration de ruTorrent

mkdir /var/www/rutorrent/conf/users/$user
cat <<'EOF' >  /var/www/rutorrent/conf/users/$user/config.php
<?php
\$scgi_port = 0;
\$scgi_host = "unix:///home/@user@/rtorrent/session/rpc.socket";
\$XMLRPCMountPoint = "/RPC00001";
\$pathToExternals = array(
    "php"   => '',               
    "curl"  => '/usr/bin/curl',  
    "gzip"  => '',               
    "id"    => '',               
    "stat"  => '/usr/bin/stat',  
);
\$topDirectory = "/home/@user@";
?>
EOF
sed -i.bak "s/@user@/$user/g;" /var/www/rutorrent/conf/users/$user/config.php
