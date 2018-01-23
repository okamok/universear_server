#!/bin/sh

eval "$(docker-machine env default)"
docker exec -it 352 /bin/bash
