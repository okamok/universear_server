#!/bin/sh

#git pull ;nginx -s stop ;kill ;nginx ; uwsgi --ini /code/mysite_uwsgi.ini


git pull
nginx -s stop
pkill -f -n 'uwsgi'
nginx
uwsgi --ini /code/mysite_uwsgi.ini


# nginx -s stop
# python manage.py runserver 0.0.0.0:8000
