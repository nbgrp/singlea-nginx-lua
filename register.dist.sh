#!/usr/bin/env sh

# SPDX-License-Identifier: BSD-3-Clause

SINGLEA_REGISTRATION_ENDPOINT="https://sso.example/client/register"
PAYLOAD_ENDPOINT="https://app.example/_singlea_payload"

SIGNATURE_PRIVATE_KEY_BITS=1024
SIGNATURE_MD_ALGORITHM="SHA256"


Fail() { echo "ERROR: $*" 1>&2; exit 1; }

set -eu

for c in openssl curl jq php ; do
  command -v $c >/dev/null 2>&1 || Fail "$c not found"
done

cd "$(realpath "$(dirname "$0")")"

test -f jose.phar && test -f jose.phar.pubkey \
    || curl -sS -OL https://github.com/web-token/jwt-app/raw/gh-pages/jose.phar -OL https://github.com/web-token/jwt-app/raw/gh-pages/jose.phar.pubkey \
    || Fail "Cannot download jose.phar utility"


####################################
#### Generate signature SSL key ####
####################################

SIGNATURE_PRIVATE_KEY="$(openssl genrsa $SIGNATURE_PRIVATE_KEY_BITS 2> /dev/null)"
SIGNATURE_PUBLIC_KEY="$(printf "%s" "$SIGNATURE_PRIVATE_KEY" | openssl rsa -pubout 2> /dev/null)"

SIGNATURE_PRIVATE_KEY="$(echo "$SIGNATURE_PRIVATE_KEY" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')"
SIGNATURE_PUBLIC_KEY="$(echo "$SIGNATURE_PUBLIC_KEY" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')"

test -z "$SIGNATURE_PRIVATE_KEY" && Fail "SIGNATURE_PRIVATE_KEY is empty"


#######################
#### Generate JWKs ####
#######################

## The choice of the type of key encryption algorithm and its other parameters depends on
## the selected content encryption algorithm (see "alg" and "enc" parameters in the following
## registration request JSON).

TOKEN_RECIPIENT_PRIVATE_JWK="$(php jose.phar key\:generate\:oct --use=enc --alg=PBES2-HS512+A256KW 2048)"
TOKEN_RECIPIENT_PUBLIC_JWK="$(php jose.phar key\:convert\:public ''"$TOKEN_RECIPIENT_PRIVATE_JWK"'')"

PAYLOAD_REQUEST_RECIPIENT_PRIVATE_JWK="$(php jose.phar key\:generate\:ec --use=enc --alg=ECDH-ES+A256KW P-256)"
PAYLOAD_REQUEST_RECIPIENT_PUBLIC_JWK="$(php jose.phar key\:convert\:public ''"$PAYLOAD_REQUEST_RECIPIENT_PRIVATE_JWK"'')"

PAYLOAD_RESPONSE_SIGNATURE_PRIVATE_JWK="$(php jose.phar key\:generate\:rsa --use=sig --alg=RS256 2048)"
PAYLOAD_RESPONSE_SIGNATURE_PUBLIC_JWK="$(php jose.phar key\:convert\:public ''"$PAYLOAD_RESPONSE_SIGNATURE_PRIVATE_JWK"'')"


##############################
#### Register application ####
##############################

CLIENT_REGISTRATION_RESPONSE="$(curl --insecure --silent --request POST ''$SINGLEA_REGISTRATION_ENDPOINT'' --header 'Content-Type: application/json' --data-raw '{
  "signature": {
    "md-alg": "'"$SIGNATURE_MD_ALGORITHM"'",
    "key": "'"$SIGNATURE_PUBLIC_KEY"'"
  },
  "token": {
    "#": "jwt",
    "ttl": 600,
    "claims": [
      "uid",
      "email",
      "role[]"
    ],
    "jws": {
      "alg": "ES256"
    },
    "jwe": {
      "alg": "PBES2-HS512+A256KW",
      "enc": "A256CBC-HS512",
      "jwk": '"$TOKEN_RECIPIENT_PUBLIC_JWK"'
    }
  },
  "payload": {
    "#": "jwt",
    "endpoint": "'"$PAYLOAD_ENDPOINT"'",
    "claims": [
      "email",
      "department"
    ],
    "request": {
      "jws": {
        "alg": "ES256K"
      },
      "jwe": {
        "alg": "ECDH-ES+A256KW",
        "enc": "A256GCM",
        "zip": "DEF",
        "jwk": '"$PAYLOAD_REQUEST_RECIPIENT_PUBLIC_JWK"'
      }
    },
    "response": {
      "jws": {
        "alg": "RS256",
        "jwk": '"$PAYLOAD_RESPONSE_SIGNATURE_PUBLIC_JWK"'
      },
      "jwe": {
        "alg": "RSA-OAEP-384",
        "enc": "A192GCM",
        "zip": "DEF"
      }
    }
  }
}')"

test -z "$CLIENT_REGISTRATION_RESPONSE" && Fail "Register request failed"

CLIENT_ID="$(echo "$CLIENT_REGISTRATION_RESPONSE" | jq -r '.client.id')"
SECRET="$(echo "$CLIENT_REGISTRATION_RESPONSE" | jq -r '.client.secret')"
TOKEN_SIGNATURE_PUBLIC_JWK="$(echo "$CLIENT_REGISTRATION_RESPONSE" | jq -c '.token.jwk')"
PAYLOAD_REQUEST_SIGNATURE_PUBLIC_JWK="$(echo "$CLIENT_REGISTRATION_RESPONSE" | jq -c '.payload.request.jwk')"
PAYLOAD_RESPONSE_RECIPIENT_PUBLIC_JWK="$(echo "$CLIENT_REGISTRATION_RESPONSE" | jq -c '.payload.response.jwk')"

for env in CLIENT_ID SECRET TOKEN_SIGNATURE_PUBLIC_JWK PAYLOAD_REQUEST_SIGNATURE_PUBLIC_JWK PAYLOAD_RESPONSE_RECIPIENT_PUBLIC_JWK ; do
  eval "test -z \$$env" && Fail "$env is empty"
done


#########################################
#### Persist generated/received data ####
#########################################

## Persist SIGNATURE_PRIVATE_KEY and SIGNATURE_MD_ALGORITHM environment variables for nginx usage (from Docker image)

#grep -q 'SINGLEA_SIGNATURE_PRIVATE_KEY=.*' docker/.env && sed -i "/^SINGLEA_SIGNATURE_PRIVATE_KEY.*/d" docker/.env && printf "SINGLEA_SIGNATURE_PRIVATE_KEY=\"%s\"\n" "$SIGNATURE_PRIVATE_KEY" >> docker/.env \
#    || printf "SINGLEA_SIGNATURE_PRIVATE_KEY=\"%s\"\n" "$SIGNATURE_PRIVATE_KEY" >> docker/.env
#grep -q 'SINGLEA_SIGNATURE_MD_ALGORITHM=.*' docker/.env && sed -i "/^SINGLEA_SIGNATURE_MD_ALGORITHM.*/d" docker/.env && printf "SINGLEA_SIGNATURE_MD_ALGORITHM=\"%s\"\n" "$SIGNATURE_MD_ALGORITHM" >> docker/.env \
#    || printf "SINGLEA_SIGNATURE_MD_ALGORITHM=\"%s\"\n" "$SIGNATURE_MD_ALGORITHM" >> docker/.env


## Persist CLIENT_ID and SECRET environment variables for nginx usage (from Docker image)

#grep -q 'SINGLEA_CLIENT_ID=.*' docker/.env && sed -i "/SINGLEA_CLIENT_ID=.*/d" docker/.env && echo "SINGLEA_CLIENT_ID=$CLIENT_ID" >> docker/.env \
#    || echo "SINGLEA_CLIENT_ID=$CLIENT_ID" >> docker/.env
#grep -q 'SINGLEA_SECRET=.*' docker/.env && sed -i "/SINGLEA_SECRET=.*/d" docker/.env && echo "SINGLEA_SECRET=$SECRET" >> docker/.env \
#    || echo "SINGLEA_SECRET=$SECRET" >> docker/.env


#mkdir -p app/config/jwt
#printf -- "%s" "$TOKEN_SIGNATURE_PUBLIC_JWK" > app/config/jwt/public.jwk || Fail "Cannot save token signature public JWK"

#mkdir -p app/config/payload
#printf -- "%s" "$PAYLOAD_REQUEST_SIGNATURE_PUBLIC_JWK" > app/config/payload/request.jwk || Fail "Cannot save payload signature public JWK"
#printf -- "%s" "$PAYLOAD_RESPONSE_RECIPIENT_PUBLIC_JWK" > app/config/payload/response.jwk || Fail "Cannot save payload recipient public JWK"

echo "Client successfully registered"
