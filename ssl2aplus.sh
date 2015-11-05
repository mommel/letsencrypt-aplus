#!/bin/bash
URLNO=$URLNO-1
FOLDER="/etc/letsencrypt/live/"
DHFILE="/etc/ssl/private/dhparams_4096.pem"
VHOSTFOLDER="/var/www/vhosts"
STARTFOLDER=$( pwd )
cd $FOLDER

move() {
  cur=$1
  way=$2
  filec=$3
  if [ "$way" = "UP" ]
  then
    cur=$(( cur - 1));
    if [ $cur -le 1 ]
    then
	cur=1
    fi
  fi
  if [ "$way" = "DOWN" ]
  then
    cur=$((cur + 1));
    if [ $cur -ge $filec ]
    then
        cur=$filec
    fi
  fi
  showTree $cur
}

showTree() {
  local up=$'\e[A'
  local up2='^[[A'
  clear
  cur=$1
  echo -e "\e[;0m\e[0;31m########################################################"
  echo -e  "\e[01;31m\e[31m FOLLOWING DOMAINS ARE AVAILABLE IN $FOLDER \e[;031m"
  echo "########################################################"
  i=0
  while read line
  do
    urlArray[ $i ]="$line"
    (( i++ )) 
  done < <(ls -d */ | cat)
  FileCount=$i
  i=0
  for filename in ${urlArray[*]}
  do
    (( i++ ))
    if [ $i = $cur ]
    then
       line="\e[1;31m█\e[0;23m$filename\e[33m"
    else
       line="\e[;30m█\e[01;2m\e[44m$filename\e[0;0m"
    fi
    echo -e $line
  done
  echo "## Please select your domain"
  echo "## You can select a domain by:"
  echo "## (w) to move up"
  echo "## (s) to move down"
  echo "## (ENTER) to select file"
  echo -e "\e[;0m"
  read -sn1 ANSWER>2;
  case $ANSWER in
    w) move $cur "UP" $FileCount;;
    s) move $cur "DOWN" $FileCount;;
    "") URLNO=$cur;;
    *) showTree $cur ;; 
  esac
}

generateApacheVhost() {
	echo -e "<VirtualHost *:80>"
	echo -e "  ServerName $CLEANURL"
	echo -e "  ServerAlias www.$CLEANURL"
	echo -e "  <Location />"
	echo -e "    Redirect 301 / https://www.$CLEANURL"
	echo -e "  </Location>"
	echo -e "</VirtualHost>"
	echo -e ""
	echo -e "<VirtualHost *:443>"
	echo -e "  ServerAdmin webmaster@localhost"
	echo -e "  ServerName $CLEANURL"
	echo -e "  ServerAlias www.$CLEANURL"
	echo -e ""
	echo -e "    SSLEngine on"
	echo -e "    SSLCompression off"
	echo -e "    SSLCipherSuite \"HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128\""
	echo -e "    SSLHonorCipherOrder on"
	echo -e "    SSLProtocol TLSv1.2"
	echo -e "    SSLUseStapling on"
	echo -e "    Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure"
	echo -e "    Header always set Public-Key-Pins \"pin-sha256=\\\"$CHAINFINGERPRINT\\\"; pin-sha256=\\\"$PRIVFINGERPRINT\\\"; max-age=31536000; includeSubDomains\""
	echo -e "    Header always set X-Frame-Options SAMEORIGIN"
	echo -e "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubdomains; preload\""
	echo -e "    Header always set X-Content-Type-Options nosniff"
	echo -e ""
	echo -e "## NEXT LINE IS REPLACED WITH THE HARDENED VERSION"
	echo -e "#   SSLCertificateFile /etc/letsencrypt/live/$URL/fullchain.pem"
	echo -e "    SSLCertificateFile /etc/letsencrypt/archive/$URL/fullchain_dhparams_4096.pem"
	echo -e "    SSLCertificateKeyFile /etc/letsencrypt/live/$URL/privkey.pem"
	echo -e "    SSLCACertificateFile /etc/letsencrypt/live/$URL/lets-encrypt-x1-cross-signed.pem"
	echo -e ""
	echo -e "    DocumentRoot \"$VHOSTFOLDER/$CLEANURL/httpdocs/\""
	echo -e "    <Directory \"$VHOSTFOLDER/$CLEANURL/httpdocs/\">"
	echo -e "      DirectoryIndex index.php index.html"
	echo -e "      Options Indexes FollowSymLinks MultiViews"
	echo -e "      AllowOverride All"
	echo -e "      Order allow,deny"
	echo -e "      allow from all"
	echo -e "    </Directory>"
	echo -e ""
	echo -e "    ErrorLog \${APACHE_LOG_DIR}/ssl_$CLEANURL.error.log"
	echo -e "    LogLevel warn"
	echo -e "    CustomLog \${APACHE_LOG_DIR}/ssl_$CLEANURL.access.log combined"
	echo -e "</VirtualHost>"
}

generateNginxVhost() {
	echo -e "server {"
    echo -e "    listen 80;"
    echo -e "#    listen [::]:80 ipv6only=on;"
    echo -e ""
    echo -e "    root $VHOSTFOLDER/$CLEANURL/httpdocs/;"
    echo -e "    index index.html index.htm"
    echo -e ""
    echo -e "    server_name $CLEANURL www.$CLEANURL;"
    echo -e ""
    echo -e "    return 301 https://$CLEANURL/$request_uri;"
    echo -e "}"
    echo -e ""
    echo -e "# HTTPS server"
    echo -e ""
    echo -e "server {"
    echo -e "        listen 443;"
    echo -e "        server_name $CLEANURL www.$CLEANURL;"
    echo -e ""
    echo -e "        root $VHOSTFOLDER/$CLEANURL/httpdocs/;"
    echo -e "        index index.html index.htm;"
    echo -e ""
    echo -e "        ssl on;"
    echo -e "        ssl_ciphers \"HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128\";"
    echo -e "        ssl_prefer_server_ciphers on;"
    echo -e "        ssl_protocols TLSv1.2;"
    echo -e ""
    echo -e "## NEXT LINE IS REPLACED WITH THE HARDENED VERSION"
    echo -e "        ssl_certificate /etc/letsencrypt/live/$URL/fullchain.pem;"
    echo -e "#       ssl_certificate /etc/letsencrypt/archive/$URL/fullchain_dhparams_4096.pem"
    echo -e "        ssl_certificate_key /etc/letsencrypt/live/$URL/privkey.pem;"
    echo -e "        ssl_session_timeout 5m;"
    echo -e ""
    echo -e "## TO REFACTOR FROM APACHE"
    echo -e "#       SSLUseStapling on"
    echo -e "#       Header edit Set-Cookie ^(.*)$ ;HttpOnly;Secure"
    echo -e "#       Header always set Public-Key-Pins \"pin-sha256=\\\"$CHAINFINGERPRINT\\\"; pin-sha256=\\\"$PRIVFINGERPRINT\\\"; max-age=31536000; includeSubDomains\""
    echo -e "#       Header always set X-Frame-Options SAMEORIGIN"
    echo -e "#       Header always set Strict-Transport-Security \"max-age=31536000; includeSubdomains; preload\""
    echo -e "#       Header always set X-Content-Type-Options nosniff"
    echo -e ""
    echo -e "        location / {"
    echo -e "          try_files $uri $uri/ =404;"
    echo -e "        }"
    echo -e "}"
}


if [ -e "$DHFILE" ]; then
  echo "DH parameters file exists will go on"
else
  echo -e "Generating DH parameters - This will last some minutes"
  read -p "Press any key to go on..."
  openssl dhparam -out "$DHFILE" 4096
fi

showTree 1
cd $STARTFOLDER
URLNO=$URLNO-1
URL=${urlArray[$URLNO]}
replace=""
URL=${URL//\//$replace}
CLEANURL=${URL//www\./$replace}
echo -e "YOU WANT TO HARDEN $URL IF NOT HIT CTRL-C"
read -p "Press any key to go on..."
cat "/etc/letsencrypt/live/$URL/fullchain.pem" "$DHFILE" > "/etc/letsencrypt/archive/$URL/fullchain_dhparams_4096.pem"
CHAINFINGERPRINT=$(openssl x509 -noout -in "/etc/letsencrypt/live/$URL/chain.pem" -pubkey | openssl asn1parse -noout -inform pem -out /tmp/fingerprint.key)
CHAINFINGERPRINT=$(openssl dgst -sha256 -binary /tmp/fingerprint.key | openssl enc -base64)
echo -e "CHAINFINGERPRINT = $CHAINFINGERPRINT"
PRIVFINGERPRINT=$(openssl x509 -noout -in "/etc/letsencrypt/live/$URL/privkey.pem" -pubkey | openssl asn1parse -noout -inform pem -out /tmp/fingerprint.key)
PRIVFINGERPRINT=$(openssl dgst -sha256 -binary /tmp/fingerprint.key | openssl enc -base64)
echo -e "PRIVFINGERPRINT = $PRIVFINGERPRINT"
echo -e " "
echo -e "This would be an example for your new A+ SSL Server"
echo -e " "
APACHE=$( generateApacheVhost )
NGINX=$( generateNginxVhost )
echo "########################"
echo -e "$APACHE"
echo "########################"
echo "$APACHE" > $STARTFOLDER/APACHE.$CLEANURL.conf
echo "$NGINX" > $STARTFOLDER/NGINX.$CLEANURL.conf
echo -e "You can find this output in APACHE/NGINX.$CLEANURL.conf"
