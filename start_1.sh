#!/bin/sh

docker-machine start ; eval "$(docker-machine env default)" ; cd /Users/user/develop/universear;docker stop 7fd 5e1 ; docker-compose start ; docker exec -it 352 /bin/bash

# nginx -s stop
# python manage.py runserver 0.0.0.0:8000
