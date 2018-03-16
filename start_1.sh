#!/bin/sh

docker-machine start ; eval "$(docker-machine env default)" ; cd /Users/user/develop/universear;docker stop d61 5e1 ae4 ; docker-compose start ; docker exec -it 352 /bin/bash
