FROM python:latest
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code

#### docker hubのprivateにアクセス
# ADD config.json /root/.docker/



#### ソースコードを取得
## git 接続に必要な準備

# ~/.ssh/for_github 秘密鍵を配置
RUN mkdir ~/.ssh
RUN chmod 777 ~/.ssh
ADD for_bit_bucket /root/.ssh/
# ADD for_github /root/.ssh/

# ~/.ssh/config を作成
ADD config /root/.ssh/
# RUN echo $'Host github.com\n\
#   HostName github.com\n\
#   IdentityFile ~/.ssh/for_github\n\
#   User git' > ~/.ssh/config

# githubをknown_hostsに登録
# RUN ssh-keyscan -t rsa github.com > ~/.ssh/known_hosts
RUN ssh-keyscan -t rsa bitbucket.org > ~/.ssh/known_hosts

# キーの権限
RUN chmod 600 /root/.ssh/*


#### apt-get update
RUN apt-get update

#### 多言語対応
RUN yes | apt-get install gettext

## git インストール〜PULL
RUN apt-get install git
RUN git init
RUN git remote add origin git@bitbucket.org:okamok/universear.git
RUN git fetch
RUN git checkout -b develop remotes/origin/develop
RUN git pull


#### mySQL client インストール
RUN pip install mysqlclient


#### uwsgi インストール
RUN pip install uwsgi


#### uwsgi 関連
## uwsgi のlog file置き場作成
# RUN mkdir /var/log/uwsgi && yes
RUN mkdir /var/log/uwsgi

## uwsgi iniを配置
ADD mysite_uwsgi.ini /code/

## params 配置
ADD uwsgi_params /code/

#### nginx 関連
## install
RUN apt-get -y install nginx

#### 開発環境でのHTTPSを実行するため 
RUN apt-get install stunnel

## 作成したnginx.confをコピー(シンボリックリンク貼る方法がうまくいかなかった)
# RUN cp /code/myweb_nginx.conf /etc/nginx/conf.d/myweb_nginx.conf
ADD myweb_nginx.conf /etc/nginx/conf.d/

#### pip install 実行
RUN pip install --upgrade -r requirements.txt


#### DB 作成
# RUN export PYENV='local'
# RUN python manage.py migrate
