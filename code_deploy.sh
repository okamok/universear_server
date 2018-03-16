#!/bin/sh
git pull
nginx -s stop
pkill -f -n 'uwsgi'
nginx
uwsgi --ini /code/mysite_uwsgi.ini
