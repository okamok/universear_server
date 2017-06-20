#!/bin/sh

docker-machine start ; eval "$(docker-machine env default)" ; cd /Users/user/develop/docker_python_nginx2;docker stop 5e1 ae4 7fd ; docker-compose start ; docker exec -it edc /bin/bash

nginx -s stop
python manage.py runserver 0.0.0.0:8000
