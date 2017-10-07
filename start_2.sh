#!/bin/sh

export PYENV="local"
nginx -s stop
python manage.py runserver 0.0.0.0:8000
