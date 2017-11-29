#!/bin/sh

eval "$(docker-machine env default)"
docker exec -it 14b78b01cfda /bin/bash
