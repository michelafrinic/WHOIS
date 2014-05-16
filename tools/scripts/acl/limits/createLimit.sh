#!/bin/sh
curl --data "@${1}" -H "Accept:application/json" -H "Content-Type:application/json" http://127.0.0.1:8885/api/acl/limits?apiKey=MYAPIKEY
