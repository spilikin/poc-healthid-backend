#!/bin/bash

#--- Config
DOMAINS=(acme.spilikin.dev appauth.acme.spilikin.dev id.acme.spilikin.dev)
CERTBOT_DIR=../.certbot/
RSA_KEY_SIZE=4096
EMAIL=cloud@spilikin.dev
STAGING=2 # set to 0 if you are ready to go, 1 for staging with let's encrypt, 2 for self-signed certs

for domain in ${DOMAINS[@]}
do
    echo "======================================"
    echo "Stage 1/2 $domain"
    echo "======================================"

    if [ ! -d "$CERTBOT_DIR/conf/live/$domain" ]; then
        path="/etc/letsencrypt/live/$domain"
        mkdir -p "$CERTBOT_DIR/conf/live/$domain"
        docker-compose run --rm --entrypoint "\
        openssl req -x509 -nodes -newkey rsa:$RSA_KEY_SIZE -days 1\
            -keyout '$path/privkey.pem' \
            -out '$path/fullchain.pem' \
            -subj '/CN=$domain'" certbot
    fi

done

docker-compose up --force-recreate -d frontgate

for domain in ${DOMAINS[@]}
do
    echo "======================================"
    echo "Stage 2/2 $domain"
    echo "======================================"

    if [ $STAGING != 2 ]
    then
        if [ ! -f "$CERTBOT_DIR/conf/live/$domain/cert.pem" ]; then
            docker-compose run --rm --entrypoint "\
                rm -Rf /etc/letsencrypt/live/$domain && \
                rm -Rf /etc/letsencrypt/archive/$domain && \
                rm -Rf /etc/letsencrypt/renewal/$domain.conf" certbot
        fi

        if [ $STAGING != 0 ]
        then
            staging_arg="--staging"
        fi

        docker-compose run --rm --entrypoint "\
        certbot certonly --webroot -w /var/www/certbot \
            $staging_arg \
            --email $EMAIL \
            --domain $domain \
            --rsa-key-size $RSA_KEY_SIZE \
            --agree-tos \
            --force-renewal" certbot
    fi


done

docker-compose up --force-recreate -d frontgate
