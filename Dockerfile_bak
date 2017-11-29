FROM python:latest
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD requirements.txt /code/
RUN pip install -r requirements.txt
RUN pip install mysqlclient
RUN pip install uwsgi
ADD . /code/
RUN apt-get update && apt-get -y install nginx
# 作成したnginx.confをコピー(シンボリックリンク貼る方法がうまくいかなかった)
RUN cp /code/myweb_nginx.conf /etc/nginx/conf.d/myweb_nginx.conf
