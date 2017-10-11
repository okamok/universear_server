#!/bin/sh

docker-machine start ; eval "$(docker-machine env default)" ; cd /Users/user/develop/docker_python_nginx2;docker stop d61 5e1 ; docker-compose start ; docker exec -it 11f /bin/bash

# nginx -s stop
# python manage.py runserver 0.0.0.0:8000
