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
deb-src http://nginx.org/packages/debian/ wheezy nginx

#mongodb source
deb http://downloads-distro.mongodb.org/repo/debian-sysvinit dist 10gen ">> /etc/apt/sources.list

#Ajout des clée

##dotdeb
cd /tmp
wget http://www.dotdeb.org/dotdeb.gpg
apt-key add dotdeb.gpg

##nginx
cd /tmp
wget http://nginx.org/keys/nginx_signing.key
apt-key add nginx_signing.key

## mongodb source

# Installation des paquets vitaux
$packetg update
$packetg safe-upgrade -y
$packetg install -y htop mongodb-10gen openssl  python build-essential libssl-dev pkg-config whois  libcurl4-openssl-dev libsigc++-2.0-dev libncurses5-dev nginx vim nano screen subversion apache2-utils curl php5 php5-cli php5-fpm php5-curl php5-geoip git unzip unrar rar zip ffmpeg buildtorrent curl mediainfo


##Working directory##
cd gaaara


git clone https://github.com/joyent/node.git
cd node
git checkout v0.10.26
./configure --openssl-libpath=/usr/lib/ssl
make
make install


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
mkdir -p /usr/local/nginx /usr/local/nginx/ssl /usr/local/nginx/pw /etc/nginx/sites-enabled
touch /etc/nginx/sites-enabled/rutorrent.conf
touch /usr/local/nginx/pw/rutorrent_passwd


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


service php5-fpm restart

###########################################################
##              Configuration serveur web                ##
###########################################################


rm /etc/nginx/nginx.conf

cat <<'EOF' > /etc/nginx/nginx.conf

worker_processes 8;
user www-data www-data;
events {
  worker_connections 1024;
}

http {
  client_max_body_size 20G; 
  include mime.types;
  default_type application/octet-stream;
  sendfile on;
  keepalive_timeout 65;
  gzip on;
  gzip_min_length 0;
  gzip_http_version 1.0;
  gzip_types text/plain text/xml application/xml application/json text/css application/x-javascript text/javascript application/javascript;
  #####
  #HTTP#
  #####
  upstream nodejs { 
    server 127.0.0.1:3001 max_fails=0 fail_timeout=0; 
  } 

  server {
    listen 80;
    server_name localhost;

    location / { 
      proxy_pass  http://nodejs; 
      proxy_max_temp_file_size 0;
      proxy_redirect off; 
      proxy_set_header Host $host ; 
      proxy_set_header X-Real-IP $remote_addr ; 
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for ; 
    } 

    location /socket.io/ {
      proxy_pass http://nodejs;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
    }

    location /rutorrent {
      root /var/www;
      index index.php index.html index.htm;
      server_tokens off;
      auth_basic "Entrez un mot de passe";
      auth_basic_user_file "/usr/local/nginx/pw/rutorrent_passwd";
    }

    location ~ \.php$ {
      root "/var/www";
      fastcgi_pass unix:/etc/phpcgi/php-cgi.socket;
      fastcgi_index index.php;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      include fastcgi_params;
    }
  }
  ######
  #SSL##
  ######
  server {
    listen 443;
    server_name localhost;
    
    ssl on;
    ssl_certificate usr /usr/local/nginx/ssl/serv.pem;
    ssl_certificate_key /usr/local/nginx/ssl/serv.key;
    
    add_header Strict-Transport-Security max-age=500; 

    location / { 
      proxy_pass  http://nodejs; 
      proxy_redirect off; 
      proxy_max_temp_file_size 0;
      proxy_set_header Host $host ; 
      proxy_set_header X-Real-IP $remote_addr ; 
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for ; 
      proxy_set_header X-Forwarded-Proto https; 
    } 

    location /socket.io/ {
      proxy_http_version 1.1;
      proxy_pass http://nodejs;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
    }

    location /rutorrent {
      auth_basic "Entrez un mot de passe";
      auth_basic_user_file "/usr/local/nginx/rutorrent_passwd";
      root /var/www;
      index index.php index.html index.htm;
      server_tokens off;
    }
    location ~ \.php$ {
      root "/var/www";
      fastcgi_pass unix:/etc/phpcgi/php-cgi.socket;
      fastcgi_index index.php;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      include fastcgi_params;
    }
  }
}
EOF

echo "include /usr/local/bin" >> /etc/ld.so.conf
ldconfig

#onfig dans php-fpm.conf
echo "
[www]
listen = /etc/phpcgi/php-cgi.socket
user = www-data
group = www-data
pm.max_children = 4096
pm.start_servers = 4
pm.min_spare_servers = 4
pm.max_spare_servers = 128
pm.max_requests = 4096
" >> /etc/php5/fpm/php-fpm.conf

mkdir /etc/phpcgi

###########################################################
##             SSL Configuration                         ##
###########################################################

#!/bin/bash

openssl req -new -x509 -days 3658 -nodes -newkey rsa:2048 -out /usr/local/nginx/ssl/serv.pem -keyout /usr/local/nginx/ssl/serv.key<<EOF
RU
Russia
Moskva
wrty
wrty LTD
wrty.com
contact@wrty.com
EOF

service nginx restart
###########################################################
##             SSL Configuration    Fin                  ##
###########################################################

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
python /root/gaaara/htpasswd.py -b /usr/local/nginx/pw/rutorrent_passwd $user ${pwd}
chmod 640 /usr/local/nginx/pw/rutorrent_passwd/*
chown -c nginx:nginx /usr/local/nginx/pw/*
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


cat <<'EOF' > /etc/init.d/$user-rtorrent
#!/bin/sh -e
# Start/Stop rtorrent sous forme de daemon.

NAME=@user@-rtorrent
SCRIPTNAME=/etc/init.d/$NAME
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

case $1 in
        start)
                echo "Starting rtorrent... "
                su -l @user@ -c "screen -fn -dmS rtd nice -19 rtorrent"
                echo "Terminated"
        ;;
        stop)
                if [ "$(ps aux | grep -e '.*rtorrent$' -c)" != 0  ]; then
                {
                        echo "Shutting down rtorrent... "
                        killall -r "^.*rtorrent$"
                        echo "Terminated"
                }
                else
                {
                        echo "rtorrent not yet started !"
                        echo "Terminated"
                }
                fi
        ;;
        restart)
                if [ "$(ps aux | grep -e '.*rtorrent$' -c)" != 0  ]; then
                {
                        echo "Shutting down rtorrent... "
                        killall -r "^.*rtorrent$"
                        echo "Starting rtorrent... "
                        su -l @user@ -c "screen -fn -dmS rtd nice -19 rtorrent"
                        echo "Terminated"
                }
                else
                {
                        echo "rtorrent not yet started !"
                        echo "Starting rtorrent... "
                        su -l @user@ -c "screen -fn -dmS rtd nice -19 rtorrent"
                        echo "Terminated"
                }
                fi
        ;;
        *)
                echo "Usage: $SCRIPTNAME {start|stop|restart}" >&2
                exit 2
        ;;
esac
EOF

sed -i.bak "s/@user@/$user/g;" /etc/init.d/$user-rtorrent

#Configuration rtorrent deamon
chmod +x /etc/init.d/$user-rtorrent
update-rc.d rtorrent defaults 99




