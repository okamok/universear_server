#!/bin/sh

docker-machine start ; eval "$(docker-machine env default)" ; cd /Users/user/develop/universear;docker stop 3e2 7fd ; docker-compose start ; docker exec -it 14b78b01cfda /bin/bash

# nginx -s stop
# python manage.py runserver 0.0.0.0:8000
