#!/bin/bash
URLNO=$URLNO-1
FOLDER="/etc/letsencrypt/live/"
VHOSTFOLDER="/var/www/vhosts"
STARTFOLDER=$( pwd )
TARGET=""
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
  urlArray[ $i ]="Renew all"
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

selectDH() {
	clear
	echo -e "Please select the size of your Diffie Hellman crypto"
	echo -e "(1) 1024 (2) 2048 (3) 4096 [default]"
	echo -e "$DHFILE1K"
	read -sn1 ANSWER;
  	case $ANSWER in
  		1) getDH "/etc/ssl/private/dhparams_1024.pem" "1024";;
		2) getDH "/etc/ssl/private/dhparams_2048.pem" "2048";;
		3) getDH "/etc/ssl/private/dhparams_4096.pem" "4096";;
		"") getDH "/etc/ssl/private/dhparams_4096.pem" "4096";;
		*) selectDH;;
	esac
}

getDH() {
	DHFILE=$1
	DHSIZE=$2
	echo -e "DH File $DHFILE"
	if [ -e "$DHFILE" ]; then
	  echo "DH parameters file exists will go on"
	else
	  echo -e "Generating DH parameters - This will last some minutes"
	  read -p "Press any key to go on..."
	  openssl dhparam -out "$DHFILE" "$DHSIZE"
	fi
}

selectTarget() {
	clear
	echo -e "Please select your System "
	echo -e "(1) Apache with openssl < 1.0.2d (2) NGINX"
	read -sn1 ANSWER;
  	case $ANSWER in
  		1) TARGET="A1";;
		2) TARGET="N";;
		*) selectTarget;;
	esac
}

generateFullchainDHFile() {
	cat "/etc/letsencrypt/live/$URL/fullchain.pem" "$DHFILE" > "/etc/letsencrypt/archive/$URL/fullchain_dhparams_4096.pem"
}

generateChainFingerprint() {
	gCHAINFINGERPRINT=$(openssl x509 -noout -in "/etc/letsencrypt/live/$URL/chain.pem" -pubkey | openssl asn1parse -noout -inform pem -out /tmp/fingerprint.key)
	gCHAINFINGERPRINT=$(openssl dgst -sha256 -binary /tmp/fingerprint.key | openssl enc -base64)
	echo -e "$gCHAINFINGERPRINT"
}

generatePrivFingerprint() {
	gPRIVFINGERPRINT=$(openssl x509 -noout -in "/etc/letsencrypt/live/$URL/privkey.pem" -pubkey | openssl asn1parse -noout -inform pem -out /tmp/fingerprint.key)
	gPRIVFINGERPRINT=$(openssl dgst -sha256 -binary /tmp/fingerprint.key | openssl enc -base64)
	echo -e "$gPRIVFINGERPRINT"
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
    echo -e "    server_name $CLEANURL;"
    echo -e "    server_name www.$CLEANURL;"
    echo -e ""
    echo -e "    return 301 https://$CLEANURL/$request_uri;"
    echo -e "}"
    echo -e ""
    echo -e "# HTTPS server"
    echo -e ""
    echo -e "server {"
    echo -e "        listen 443;"
    echo -e "        server_name $CLEANURL"
    echo -e "        server_name www.$CLEANURL;"
    echo -e ""
    echo -e "        root $VHOSTFOLDER/$CLEANURL/httpdocs/;"
    echo -e "        index index.html index.htm;"
    echo -e ""
    echo -e "        ssl on;"
    echo -e "        ssl_ciphers \"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA\";"
    echo -e "        ssl_prefer_server_ciphers on;"
    echo -e "        ssl_protocols TLSv1.2;"
    echo -e "        ssl_session_cache shared:SSL:10m;"
    echo -e ""
    echo -e "## NEXT LINE IS REPLACED WITH THE HARDENED VERSION"
    echo -e "        ssl_certificate /etc/letsencrypt/live/$URL/fullchain.pem;"
    echo -e "        ssl_dhpharam $DHFILE";
    echo -e "        ssl_certificate_key /etc/letsencrypt/live/$URL/privkey.pem;"
    echo -e "        ssl_session_timeout 5m;"
    echo -e "        ssl_stapling on;"
    echo -e ""
    echo -e "        add_header Set-Cookie \"HttpOnly\";"
    echo -e "        add_header Set-Cookie \"Secure\";"
    echo -e "        add_header Public-Key-Pins \"pin-sha256=\\\"$CHAINFINGERPRINT\\\"; pin-sha256=\\\"$PRIVFINGERPRINT\\\"; max-age=31536000; includeSubDomains\";"
    echo -e "        add_header X-Frame-Options SAMEORIGIN;"
    echo -e "        add_header Strict-Transport-Security \"max-age=31536000; includeSubdomains; preload\";"
    echo -e "        add_header X-Content-Type-Options nosniff;"
    echo -e ""
    echo -e "        location / {"
    echo -e "          index index.htm index.html"
    echo -e "        }"
    echo -e "}"
}

clear
selectDH
selectTarget
showTree 1
cd $STARTFOLDER
URLNO=$URLNO-1
URL=${urlArray[$URLNO]}
replace=""
URL=${URL//\//$replace}
CLEANURL=${URL//www\./$replace}
echo -e "YOU WANT TO HARDEN $URL IF NOT HIT CTRL-C"
read -p "Press any key to go on..."
CHAINFINGERPRINT=$( generateChainFingerprint )
echo -e "CHAINFINGERPRINT = $CHAINFINGERPRINT"
PRIVFINGERPRINT=$( generatePrivFingerprint )
echo -e "PRIVFINGERPRINT = $PRIVFINGERPRINT"
echo -e " "
echo -e "This would be an example for your new A+ SSL Server"
echo -e " "

if [ TARGET = "A1" ]
then
	APACHE=$( generateApacheVhost )
	echo "########################"
	echo -e "$APACHE"
	echo "########################"
	echo "$APACHE" > $STARTFOLDER/APACHE.$CLEANURL.conf
fi
if [ TARGET = "N" ]
then
	NGINX=$( generateNginxVhost )
	echo "########################"
	echo -e "$NGINX"
	echo "########################"
	echo "$NGINX" > $STARTFOLDER/NGINX.$CLEANURL.conf
fi
echo -e "You can find this output in APACHE/NGINX.$CLEANURL.conf"
