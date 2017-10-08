#!/bin/sh

eval "$(docker-machine env default)"
docker exec -it 11f /bin/bash
