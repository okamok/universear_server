#!/bin/sh

nginx -s stop
python manage.py runserver 0.0.0.0:8000