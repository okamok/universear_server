#!/bin/sh

eval "$(docker-machine env default)"
docker exec -it edc /bin/bash
