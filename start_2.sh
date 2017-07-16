#!/bin/sh

export PYENV="develop"
nginx -s stop
python manage.py runserver 0.0.0.0:8000
