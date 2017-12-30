import os
import json
import base64
import subprocess
from subprocess import Popen

from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.template import loader
from django.views import generic
from django.utils import timezone

from pprint import pprint

from hlar.models import User, Target, Payment, AccessLog, Oauth as OauthTbl
from django.db.models import Count
from hlar.forms import TargetForm, UserForm, RegistrationForm
from hlar.vuforiaAPI import add_target, get_targets, get_targets_user_id, judge_vws_result, get_target_id_from_name, update_target, del_target, get_target_by_id, duplicates
# from hlar.twitterAPI import get_twitter_account
from hlar.lib import get_targets_popular

from hlar.models import DEFAULT_PASS


import oauth2 as oauth
import django_filters
from rest_framework import viewsets, filters
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response
from hlar.serializer import UserSerializer, TargetSerializer, AccessLogSerializer

# from boto3.s3.key import Key
# from boto3.s3.connection import S3Connection
import boto3
from boto3.s3.transfer import S3Transfer

import urllib
# import twitter
from requests_oauthlib import OAuth1Session

# DB登録時のバリデーション
from django.core.exceptions import ValidationError

# ログイン状態を判別する為に必要
from django.contrib.auth.decorators import login_required

# signup
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
# from django.shortcuts import render, redirect
from hlar.forms import SignUpForm

import social_django

from django.contrib.auth.hashers import make_password

from django.contrib import messages

from django.utils.translation import ugettext as _

from django.core.mail import EmailMessage

from registration.views import RegistrationView
from django.contrib.sites.shortcuts import get_current_site

from django.db import IntegrityError

from django.conf import settings

from user_agents import parse as parse_ua

import stripe

import string
import random

# from sorl.thumbnail import get_thumbnail

# 画像のリサイズに使用
from PIL import Image
from io import BytesIO
from django.core.files.base import ContentFile
from PIL import ExifTags

# import StringIO
# from io import StringIO
# from django.core.files.uploadedfile import InMemoryUploadedFile
# uastring_mobile = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4'


import re

TARGET_FILE_PATH = './static/images/'

bucket_name = settings.S3_BUCKET_NAME
s3_FQDN = 'https://' + bucket_name + '.s3.amazonaws.com/'


def hlar_top(request):
    # proc = Popen( cmd .strip().split(" ") )
    # proc = Popen('sleep 1m',shell=True )

    # proc = Popen("python manage.py deltarget '9b53b41daa1143bd9428dd09b957d926'",shell=True )


    # proc = subprocess.call('sleep 1m' , shell=True)
    # os.system('sleep 1m')

    # check = commands.getoutput("python manage.py deltarget 111")
    # print(check)

    current_site = get_current_site(request)
    print(current_site.domain)

    # EmailMessage(u'件名', u'本文', to = ['hiliberate2013@gmail.com']).send()

    # access_token, access_token_secret = callback(request)
    #
    # if access_token is not None and access_token_secret is not None:
    #     print('login ok!')
    #     # API実行
    #     # client(access_token, access_token_secret)
    # else:
    #     print('login ng...')

    print('auth')
    print(request.user.is_authenticated())
    print(request.user.username)
    print(request.user)
    pprint(vars(request.session))
    # if request.session._session_cache != None
    #     print(request.session._session_cache['_auth_user_id'])  #idが取れてる。

    # user = authenticate(username='aaa@test.jp', password='masahi0205')
    # pprint(vars(user))
    # print(type(user))
    #


    if request.user.is_authenticated() == False:
        try:
            # oauth で返ってきた時はsessionにid が入っているのでそれを取得する。
            user = User.objects.filter(id=request.session._session_cache['_auth_user_id'])[0]

            print(user.email)
            print(DEFAULT_PASS)

            user_auth = authenticate(username=user.email, password=DEFAULT_PASS)
            login(request, user_auth)

            # これで一応nameは取れたが根本的にログインが出来ていない。
            # user = User.objects.filter(id=request.session._session_cache['_auth_user_id'])[0]
            # request.user = user
        except Exception as e:
            print('error')

    # user = User.objects.filter(id=32)[0]
    # # # user['backend'] = 'django.contrib.auth.backends.ModelBackend'
    # # print(type(user))
    #
    # request.user = user

    # backend = request.backend
    # token = _make_token(request, backend)
    # # OAuthでの認証に成功した場合のみuserが返ってくる
    # user = backend.do_auth(token, user=request.user)
    #
    # login(request, user)
    # print('aabb')
    # pprint(request.user.id)



    # 人気ターゲット一覧を取得
    targets = get_targets_popular()

    ua = parse_ua(request.META['HTTP_USER_AGENT'])


    return render(request,
                  'hlar/hlar_top.html',     # 使用するテンプレート
                  {
                    'user': request.user,
                    'msg': _("使い方"),
                    'targets': targets,
                    's3_FQDN': s3_FQDN,
                    'is_mobile': ua.is_mobile,
                  }         # テンプレートに渡すデータ
                  )


def signup(request):
    if request.method == 'POST':
        print('post-data')
        pprint(vars(request.POST))
        form = SignUpForm(request.POST)

        print('form-data')
        print(form)

        if form.is_valid():

            # この方法でupdate出来る
            # a = User.objects.get(pk=1)
            # f = SignUpForm(request.POST, instance=a)
            # f.save()


            form.save()


            user_obj = User.objects.filter(email=form.cleaned_data.get('email'))[0]
            password = user_obj.password

            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            # user = authenticate(username=username, password=raw_password)
            user = authenticate(username=form.cleaned_data.get('email'), password=raw_password)
            login(request, user)
            return HttpResponseRedirect('/hlar')
    else:
        form = SignUpForm()
    return render(request, 'hlar/signup.html', {'form': form})



def hlar_user_manage(request):





    # ######## アクセストークンを取得
    # access_token, access_token_secret = callback(request)
    #
    # ######## ユーザー登録されているのか？
    # if access_token is not None and access_token_secret is not None:
    #     oauth_object = OauthTbl.objects.filter(access_token=access_token)
    #
    #     print('access_token')
    #     print(access_token)
    #
    #     print('oauth_object')
    #     print(type(oauth_object))
    #
    #     if len(oauth_object) > 0:
    #         #### アクセストークンが存在している。
    #         ## ログイン処理 @ToDo
    #
    #
    #         ## topページにリダイレクト
    #         return HttpResponseRedirect('../../')
    #     else:
    #         #### アクセストークンが存在していない場合
    #         # (twitterなどの)IDを取得
    #         twitter_account = get_twitter_account(consumer_key, consumer_secret, access_token, access_token_secret)
    #         print('asdf')
    #         print(twitter_account)
    #         id_in_app = twitter_account['id']
    #         screen_name = twitter_account['screen_name']
    #
    #         ## (twitterなどの)ID(DBに持つ)を照会して確認。
    #         # oauth_object = OauthTbl.objects.get(id_in_auth_app=id_in_app)
    #         # oauth_object_cnt = OauthTbl.objects.get(id_in_auth_app=id_in_app).count()
    #         oauth_object = OauthTbl.objects.filter(id_in_auth_app=id_in_app)
    #         oauth_object_cnt = OauthTbl.objects.filter(id_in_auth_app=id_in_app).count()
    #
    #
    #         print("oauth_object-aaaaa")
    #         pprint(vars(oauth_object))
    #         print(oauth_object_cnt)
    #
    #         if oauth_object_cnt > 0:
    #             ## 一致する場合はoauth.access_token / access_token_secretを更新
    #             print(access_token)
    #             pprint(vars(oauth_object[0]))
    #
    #             oauth_get_obj = OauthTbl.objects.get(id_in_auth_app=id_in_app)
    #             oauth_get_obj.access_token = access_token
    #             oauth_get_obj.access_token_secret = access_token_secret
    #
    #             try:
    #                 oauth_get_obj.save()
    #             except Exception as e:
    #                 print(e.message)
    #                 print(type(e))
    #
    #             ## ログイン処理 @ToDo
    #
    #             print('aaaa')
    #         else:
    #             ## 一致しない場合は本当に登録がないのでuser に登録するフォームへ遷移
    #
    #             ## アクセストークンを登録
    #             # oauth
    #             oauth_obj = OauthTbl()
    #             oauth_obj.access_token = access_token
    #             oauth_obj.access_token_secret = access_token_secret
    #             oauth_obj.id_in_auth_app = id_in_app
    #             oauth_obj.save()
    #
    #             print('bbbb')
    #             print(oauth_obj.id)
    #
    #             # 入力フォームで使うものをsessionに保存
    #             user = {}
    #             user['oauth_id'] = oauth_obj.id
    #             user['name'] = screen_name
    #             user['mail'] = ''   #@ToDo
    #
    #             request.session['user_info'] = user
    #
    #             return HttpResponseRedirect('../../user/add/')
    #
    #
    # else:
    #     print('login ng...')


    return HttpResponseRedirect('../../')

def callback(request):
    # oauth_token と oauth_verifier を取得
    oauth_token = request.GET.get(key="oauth_token", default="")
    oauth_verifier = request.GET.get(key="oauth_verifier", default="")

    query = {}

    if oauth_token != "" and oauth_verifier != "":
        query['oauth_token'] = oauth_token
        query['oauth_verifier'] = oauth_verifier

    if not query:
        return None, None

    oauth_token_secret = request.session['oauth_token_secret']  #sessionから取得

    # Access_token と access_token_secret を取得
    consumer = oauth.Consumer(key=consumer_key, secret=consumer_secret)
    token = oauth.Token(query['oauth_token'], query['oauth_verifier'])
    client = oauth.Client(consumer, token)
    resp, content = client.request(access_token_url, "POST", body="oauth_verifier=%s" % query['oauth_verifier'])

    # print('access_token_url')
    # print(access_token_url)
    #
    # print('oauth_verifier')
    # print(query['oauth_verifier'])
    #
    # print('content')
    # print(content)
    #
    # print('resp')
    # print(resp)
    #

    content_str = content.decode('utf-8')
    access_token = dict(parse_qsl(content_str))

    # print('access_token')
    # print(access_token)

    ######## access_token と access_token_secret がDBに存在しないものならば保存
    # oauth_object = OauthTbl.objects.filter(access_token=access_token['oauth_token'])

    # if not oauth_object:
    #     #### 新規登録
    #
    #     # oauth
    #     oauth_obj = OauthTbl()
    #     oauth_obj.access_token = access_token['oauth_token']
    #     oauth_obj.access_token_secret = access_token['oauth_token_secret']
    #     oauth_obj.save()
    #
    #     # user
    #     oauth_user_insert(consumer_key, consumer_secret, access_token['oauth_token'], access_token['oauth_token_secret'])
    #     # oauth_object.access_token = access_token['oauth_token']
    #     # oauth_object.access_token_secret = access_token['oauth_token_secret']
    #     # oauth_object.save()






    return access_token['oauth_token'], access_token['oauth_token_secret']

# def client(access_token, access_token_secret):
#     # api = twitter.Api(consumer_key=consumer_key,
#     #                   consumer_secret=consumer_secret,
#     #                   access_token_key=access_token,
#     #                   access_token_secret=access_token_secret,
#     #                   cache=None)
#     #
#     # tweets = api.GetSearch(term=u"#今日")
#     # for tweet in tweets:
#     #     print(tweet.text)
#
#
#     CK = consumer_key                             # Consumer Key
#     CS = consumer_secret         # Consumer Secret
#     AT = access_token            # Access Token
#     AS = access_token_secret     # Accesss Token Secert
#
#     # タイムライン取得用のURL
#     url = "https://api.twitter.com/1.1/statuses/home_timeline.json"
#
#     # とくにパラメータは無い
#     params = {}
#
#     # OAuth で GET
#     twitter = OAuth1Session(CK, CS, AT, AS)
#     req = twitter.get(url, params = params)
#
#     if req.status_code == 200:
#         # レスポンスはJSON形式なので parse する
#         timeline = json.loads(req.text)
#         # 各ツイートの本文を表示
#         for tweet in timeline:
#             print(tweet["text"])
#
#     else:
#         # エラーの場合
#         print ("Error: %d" % req.status_code)


def user_add(request):
    msg = {}

    if request.method == 'POST':
        #### post時
        print('post')
        user_entity = User()
        user_entity.mail = request.POST['user_mail']
        user_entity.name = request.POST['user_name']
        user_entity.password = request.POST['user_password']
        user_entity.oauth_id = request.POST['user_oauth_id']

        # validation
        try:
            # user.full_clean()
            user_entity.clean()

            # save
            user_entity.save()

            # 認証メール 送信 @ToDo

            msg['success_msg'] = 'ユーザー登録が完了しました。'
        except ValidationError as e:
            # non_field_errors = e.message_dict[NON_FIELD_ERRORS]
            pprint(vars(e))
            print(e.message)
            msg['error_msg'] = e.message


    user = {}

    if 'user_entity' in locals():
        user['mail'] = user_entity.mail
        user['name'] = user_entity.name
        user['oauth_id'] = user_entity.oauth_id

    elif 'user_info' in request.session:
        print(request.session['user_info'])
        user['oauth_id'] = request.session['user_info']['oauth_id']
        user['name'] = request.session['user_info']['name']

    return render(request,
                  'hlar/user_form.html',  # 使用するテンプレート
                  {'user': user, 'msg': msg})         # テンプレートに渡すデータ


def user_edit(request, user_id=None):

    msg = {}

    print(user_id)

    if request.method == "POST":
        mode = request.POST["mode"]

        if mode == 'add':
            form = UserForm(data=request.POST)  # ← 受け取ったPOSTデータを渡す

            print('11111111')
            print(form)
        elif mode == 'edit':
            # blog = Blog.objects.get(hogehoge)
            user = get_object_or_404(User, pk=user_id)
            print('123456')
            print(user)
            # form = UserForm(request, user)
            form = UserForm(request.POST or None, instance=user)
            print(form)

        # user_entity.clean()
        # form.clean()

        if form.is_valid():  # ← 受け取ったデータの正当性確認
            print('save_ok')

            if mode == 'add':
                form.save()
                msg['success_msg'] = '更新が完了しました。'

            elif mode == 'edit':
                # print('password')
                # print(request.POST['password'])

                if request.POST.get('password', False):
                    user.set_password(request.POST['password'])

                form = form.save()

                if request.POST.get('password', False):
                    # msg['success_msg'] = 'パスワードを変更したので改めてログインして下さい。'

                    messages.success(request, 'パスワードを変更したので改めてログインして下さい。')

                    print('messages')
                    pprint(vars(messages))

                    return HttpResponseRedirect('/login')
                else:
                    msg['success_msg'] = '更新が完了しました。'

                user = get_object_or_404(User, pk=user_id)
                form = UserForm(instance=user)  # target インスタンスからフォームを作成


            # form.user_edit()
            # pass  # ← 正しいデータを受け取った場合の処理
        else:
            print('save_error')
            pass
    else:         # target_id が指定されていない (追加時)
        if user_id:   # target_id が指定されている (修正時)
            user = get_object_or_404(User, pk=user_id)
        else:
            user = User()
        form = UserForm(instance=user)  # target インスタンスからフォームを作成

    # print('aa11')
    # print(form)
    #
    # for field in form:
    #     print(field.name)


    return render(
        request,
        'hlar/user_edit.html',
        {
            'form':form,
            'user_id':user_id,
            'user': request.user,
            'msg': msg,
        }
    )



    # if request.method == 'POST':
    #     #### post時
    #     print('post')
    #     user_entity = User()
    #     user_entity.mail = request.POST['user_mail']
    #     user_entity.name = request.POST['user_name']
    #     user_entity.password = request.POST['user_password']
    #     user_entity.oauth_id = request.POST['user_oauth_id']
    #
    #     # validation
    #     try:
    #         # user.full_clean()
    #         user_entity.clean()
    #
    #         # save
    #         user_entity.save()
    #
    #         # 認証メール 送信 @ToDo
    #
    #         msg['success_msg'] = 'ユーザー登録が完了しました。'
    #     except ValidationError as e:
    #         # non_field_errors = e.message_dict[NON_FIELD_ERRORS]
    #         pprint(vars(e))
    #         print(e.message)
    #         msg['error_msg'] = e.message
    #
    #
    # user = {}
    #
    # if 'user_entity' in locals():
    #     user['mail'] = user_entity.mail
    #     user['name'] = user_entity.name
    #     user['oauth_id'] = user_entity.oauth_id
    #
    # elif 'user_info' in request.session:
    #     print(request.session['user_info'])
    #     user['oauth_id'] = request.session['user_info']['oauth_id']
    #     user['name'] = request.session['user_info']['name']
    #
    # return render(request,
    #               'hlar/user_form.html',  # 使用するテンプレート
    #               {'user': user, 'msg': msg})         # テンプレートに渡すデータ
    #



@login_required
def target_list(request):

    if request.user.is_authenticated() == False:
        return HttpResponseRedirect('/accounts/login/?next=%s' % request.path)

    # if not request.user:
    #         return HttpResponseRedirect('/login/?next=%s' % request.path)

    # if not request.user.is_authenticated():
    #         return HttpResponseRedirect('/login/?next=%s' % request.path)

#    return HttpResponse('ターゲットの一覧')
    # targets = Target.objects.all().order_by('id')

    # ua = parse_ua(uastring_mobile)
    ua = parse_ua(request.META['HTTP_USER_AGENT'])

    # print('-is_mobile: {0}'.format(ua.is_mobile))

    print('req_id')
    print(request.user)

    # ターゲット一覧を取得
    targets = get_targets_user_id(request.user.id)

    print ('type:' + str(type(targets)))
    print (len(targets))

    addTarget = True
    if len(targets) >= settings.TARGET_LIMIT_COUNT:
        addTarget = False

    return render(request,
                  'hlar/target_list.html',     # 使用するテンプレート
                  {'targets': targets,
                   's3_FQDN': s3_FQDN,
                   'is_mobile': ua.is_mobile,
                   'addTarget': addTarget,
                   'TARGET_LIMIT_COUNT': settings.TARGET_LIMIT_COUNT,
                  })         # テンプレートに渡すデータ

def target_edit(request, target_id=None):

    # # 被りある
    # response_duplicate = duplicates('4a1740ea01424b13af795935224584dd')
    #
    # # 被りなし
    # # response_duplicate = duplicates('bc5eb6aa76a14b1d83afe7b23393b40f')
    #
    # print('response_duplicate999')
    # print(response_duplicate)
    #
    # print('response_duplicate_response')
    # print(response_duplicate['result_code'])
    #
    # print('response_duplicate_similar_targets')
    # print(response_duplicate['result_code'])
    # print(len(response_duplicate['similar_targets']))



    targetFile = None

    if request.user.is_authenticated() == False:
        return HttpResponseRedirect('/accounts/login/?next=%s' % request.path)

    msg = ''
    buy_history = 0

    if target_id:   # target_id が指定されている (修正時)
        target = get_object_or_404(Target, pk=target_id)

        # 300回の購入履歴があるか確認
        payments_object = Payment.objects.filter(target_id=str(target_id), brought_view_count=300)
        print('------payments-------')
        print(len(payments_object))

        buy_history = len(payments_object)
        # print('edit1')
        # pprint(vars(target))
    else:         # target_id が指定されていない (追加時)
        #### 登録がMAX数に達していたら一覧に飛ばす
        # ターゲット一覧を取得
        targets = get_targets_user_id(request.user.id)
        if len(targets) >= settings.TARGET_LIMIT_COUNT:
            return redirect('hlar:target_list')

        target = Target()


    if request.method == 'POST':
        # POST 時

        ######## 入力チェック
        err = False
        errMsg = ''

        #### 名前
        if request.POST['target_name'] == '':
            # エラー
            err = True
            errMsg = '名前を入力して下さい。'
        else:
            target.name = request.POST['target_name']

        #### 誘導リンク
        target.target_link_URL = request.POST['target_link_URL']

        #### ターゲット @ToDo
        if err == False and request.FILES.get('target', False):
            # targetFile = request.FILES['target']
            ## ターゲット画像をresize
            targetFile = resize_img(request.FILES['target'])
            targetName = request.FILES['target'].name

            ## サイズチェック
            if targetFile and (targetFile.size > settings.TARGET_SIZE_LIMIT):
                # エラー
                err = True
                errMsg = 'ターゲット画像のサイズが制限({0}MB)を超えています。'.format(int(settings.TARGET_SIZE_LIMIT / 1000000))

            ## 拡張子チェック
            ext = os.path.splitext(targetName)[1].lower()

            print('ext')
            print(ext)

            if ext != '.jpeg' and ext != '.jpg':
                # エラー
                err = True
                errMsg = 'ターゲット画像のファイル形式が不正です。'


        #### コンテンツ
        if err == False and request.FILES.get('contents', False):
            contentsFile = request.FILES['contents']
            print('file_size')
            print(contentsFile.size)

            ## サイズチェック
            if contentsFile and (contentsFile.size > settings.CONTENTS_SIZE_LIMIT):
                # エラー
                err = True
                errMsg = 'コンテンツ動画のサイズが制限({0}MB)を超えています。'.format(int(settings.CONTENTS_SIZE_LIMIT / 1000000))

            ## 拡張子チェック
            ext = os.path.splitext(contentsFile.name)[1].lower()

            print('ext')
            print(ext)

            if ext != '.mp4' and ext != '.mov':
                # エラー
                err = True
                errMsg = 'コンテンツ動画のファイル形式が不正です。'

        if (request.FILES.keys() >= {'target'} and request.FILES.keys() >= {'contents'}) or \
            (request.FILES.keys() <= {'target'} and request.FILES.keys() <= {'contents'}):
            print('errなし')
        else:
            err = True
            errMsg = 'ターゲットとコンテンツは同時にアップして下さい。'

        if err:
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_edit.html', dict(
                msg= errMsg,
                form = form,
                target_id = target_id,
                target = target,
                stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                buy_history = buy_history,
                s3_FQDN = s3_FQDN,
                TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
            ))


        ######## ターゲットファイル
        #### まず一時的にサーバーに保存
        # 保存パス(ファイル名含む)
        encTargetFile = None
        filePathTarget = None


        # ランダム文字列を作成
        n = 9
        random_str = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])

        if request.FILES.keys() >= {'target'}:

            #targetFile = request.FILES['target']

            # filePathTarget = TARGET_FILE_PATH + random_str + '_' + targetFile.name
            #
            # print("filePathTarget")
            # print(filePathTarget)
            #
            # # ファイルが存在していれば削除
            # if default_storage.exists(filePathTarget):
            #     default_storage.delete(filePathTarget)
            #
            # try:
            #     # ファイルを保存
            #     destination = open(filePathTarget, 'wb+')
            #     for chunk in targetFile.chunks():
            #         destination.write(chunk)
            #     destination.close()
            #
            # except Exception as e:
            #     print ('=== エラー内容 ===')
            #     print ('type:' + str(type(e)))
            #     print ('args:' + str(e.args))
            #     print ('message:' + e.message)
            #     print ('e自身:' + str(e))
            #
            # # file読み込み
            # with open(filePathTarget, 'rb') as f:
            #     contents = f.read()

            # base64でencode
            # encTargetFileBase64 = base64.b64encode(contents)
            encTargetFileBase64 = base64.b64encode(targetFile.read())
            encTargetFile = encTargetFileBase64.decode('utf-8')

        ######## 誘導先 リンク
        target_link_URL = request.POST['target_link_URL']

        ######## ターゲット名
        target_name = request.POST['target_name']

        ######## meta テキスト
        #### テキスト作成
        encMetaFile = None
        metaPath = None
        if request.FILES.keys() >= {'contents'} or request.POST['hid_content_name']:

            content_name_for_meta = ''
            target_name_for_meta = ''
            if request.FILES.keys() >= {'contents'}:
                contentsFile = request.FILES['contents']
                # targetFile = request.FILES['target']

                # content_name_for_meta = random_str + '_' + contentsFile.name
                # target_name_for_meta =  random_str + '_' + targetName
                content_name_for_meta = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)
                target_name_for_meta =  random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)


            elif request.POST['hid_content_name']:
                content_name_for_meta = request.POST['hid_content_name']
                target_name_for_meta = request.POST['target_file_name']

            # meta_file_name = targetFile.name.replace('.','') + '.txt'
            meta_file_name = target_name.replace('.','') + '.txt'
            metaPath = TARGET_FILE_PATH + meta_file_name

            metaContent = "{\n" \
                            '\t"title": "' + target_name + '",\n' \
                            '\t"url" : "' + s3_FQDN + content_name_for_meta + '",\n' \
                            '\t"linkUrl" : "' + target_link_URL + '",\n' \
                            '\t"targetImageUrl" : "' + s3_FQDN + target_name_for_meta + '"\n' \
                           '}'

            # ファイルが存在していれば削除
            if default_storage.exists(metaPath):
                default_storage.delete(metaPath)

            # ファイル保存
            default_storage.save(metaPath, ContentFile(metaContent))

            # file読み込み
            with open(metaPath, 'rb') as f:
                contents = f.read()

            # base64でencode
            encMetaFileBase64 = base64.b64encode(contents)
            encMetaFile = encMetaFileBase64.decode('utf-8')
            print("encMetaFile")
            print(encMetaFile)


        ######## Vuforia API で登録
        if target_id:
            # target_id が指定されている (修正時)
            data = {
                "name": target_name,
                # "width": 1,
                "width": 320,
                # "image": encTargetFile,
                # "application_metadata": encMetaFile,
                "active_flag": 1,
            }

            if encTargetFile != None:
                data['image'] = encTargetFile

            if encMetaFile != None:
                data['application_metadata'] = encMetaFile

            response_content = update_target(target.vuforia_target_id, data)

        else:
            # target_id が指定されていない (追加時)
            response_content = add_target(max_num_results='',
                                     include_target_data=encMetaFile,
                                     image=encTargetFile,
                                     target_name=target_name)

        print('4444')
        print(response_content)

        if judge_vws_result(response_content['result_code']):
            filePathContents = None

            ######## Check for Duplicate Targets 同じターゲットが登録されていないか確認
            vuforia_target_id = ''
            if target_id:
                vuforia_target_id = target.vuforia_target_id
            else:
                vuforia_target_id = response_content['target_id']

            response_duplicate = duplicates(vuforia_target_id)
            print('response_duplicate')
            print(response_duplicate)

            # # 被りある
            # response_duplicate = duplicates('4a1740ea01424b13af795935224584dd')
            #
            # # 被りなし
            # # response_duplicate = duplicates('bc5eb6aa76a14b1d83afe7b23393b40f')
            #
            # print('response_duplicate999')
            # print(response_duplicate)
            #
            # print('response_duplicate_response')
            # print(response_duplicate['result_code'])
            #
            # print('response_duplicate_similar_targets')
            # print(response_duplicate['similar_targets'])
            # print(len(response_duplicate['similar_targets']))



            if response_duplicate['result_code'] == 'Success' and len(response_duplicate['similar_targets']) > 0:
                #### 同じ画像が登録されている

                #### 削除は不可 TargetStatusProcessing というエラーが返って来る。
                #### 登録したデータを削除 Vuforia API
                # response_content = del_target(vuforia_target_id)
                # print('del_response')
                # print(response_content)

                #### 上記削除が不可の為、当面inActiveにする。 これも不可 TargetStatusNotSuccess となる。
                # data = {"active_flag": 0}
                # response_content = update_target(vuforia_target_id, data)
                # print('del_response')
                # print(response_content)

                # バッチで実行
                # os.system('python manage.py deltarget 123456789')
                proc = Popen("python manage.py deltarget '" + vuforia_target_id + "'",shell=True )

                # エラー時
                form = TargetForm(instance=target)  # target インスタンスからフォームを作成

                if target.vuforia_target_id:
                    vuforia_target = get_target_by_id(target.vuforia_target_id)
                    target.name = vuforia_target['name']

                # 一時ファイル削除
                delete_tmp_file(filePathTarget, metaPath, filePathContents)

                return render(request, 'hlar/target_edit.html', dict(
                    msg='類似画像がすでに登録されていた為、登録出来ませんでした。',
                    form = form,
                    target_id = target_id,
                    target = target,
                    stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                    buy_history = buy_history,
                    s3_FQDN = s3_FQDN,
                    TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                    CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
                ))


            else:
                ######## S3にコンテンツ(動画)を保存
                key_name = ''
                if request.FILES.keys() >= {'contents'}:

                    # #### まず一時的にサーバーに保存
                    # # 保存パス(ファイル名含む)
                    # filePathContents = TARGET_FILE_PATH + random_str + '_' + contentsFile.name
                    #
                    # print("filePathContents")
                    # print(filePathContents)
                    #
                    # # ファイルが存在していれば削除
                    # if default_storage.exists(filePathContents):
                    #     default_storage.delete(filePathContents)
                    #
                    # try:
                    #     # ファイルを保存
                    #     destination = open(filePathContents, 'wb+')
                    #     for chunk in contentsFile.chunks():
                    #         destination.write(chunk)
                    #     destination.close()
                    #
                    # except Exception as e:
                    #     print ('=== エラー内容 ===')
                    #     print ('type:' + str(type(e)))
                    #     print ('args:' + str(e.args))
                    #     print ('message:' + e.message)
                    #     print ('e自身:' + str(e))

                    key_name = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)

                    print("key_name")
                    print(key_name)

                    #### S3にアップロード
                    client = boto3.client('s3')
                    transfer = S3Transfer(client)
                    # transfer.upload_file(filePathContents, bucket_name, key_name, extra_args={'ContentType': "video/quicktime"})
                    # transfer.upload_fileobj(contentsFile.read(), bucket_name, key_name, extra_args={'ContentType': "video/quicktime"})

                    #s3にアップした動画を公開する
                    # s3 = boto3.resource('s3')
                    # bucket = s3.Bucket(bucket_name)
                    # obj = bucket.Object(key_name)
                    # obj.

                    # アップしたコンテンツを公開状態にする
                    s3 = boto3.resource('s3')
                    bucket = s3.Bucket(bucket_name)
                    # bucket.upload_fileobj(contentsFile.read(), key_name, extra_args={'ContentType': "video/quicktime"})

                    # print("contentsFile.read()")
                    # print(contentsFile.read())

                    bucket.upload_fileobj(contentsFile, key_name)

                    object_acl = s3.ObjectAcl(bucket_name, key_name)
                    response = object_acl.put(ACL='public-read')

                    # #s3の動画のcontent-type をセットする
                    # s3 = boto3.resource('s3')
                    # s3_object = s3.get_object(Bucket=bucket_name,Key=key_name)
                    # response = s3_object.put(ContentType='string')



                ######## S3にターゲット(image)を保存
                if request.FILES.keys() >= {'target'}:
                    # client = boto3.client('s3')
                    # transfer = S3Transfer(client)
                    key_name_target = random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)
                    # transfer.upload_file(filePathTarget, bucket_name, key_name_target, extra_args={'ContentType': "image/jpeg"})
                    if s3 == None:
                        s3 = boto3.resource('s3')

                    if bucket == None:
                        bucket = s3.Bucket(bucket_name)


                    # print("targetFile.size")
                    # print(targetFile.name)
                    # print(targetFile.size)
                    # print(targetFile.read())
                    # bucket.upload_fileobj(targetFile, key_name_target)
                    targetFile.seek(0, 0)
                    bucket.upload_fileobj(targetFile, key_name_target)


                    object_acl = s3.ObjectAcl(bucket_name, key_name_target)
                    response = object_acl.put(ACL='public-read')


                ######## DBに登録
                if key_name != '':
                    target.content_name = key_name

                if request.FILES.keys() >= {'target'}:
                    target.img_name = random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)

                if target_link_URL:
                    target.target_link_URL = target_link_URL

                if target_id:   # target_id が指定されている (修正時)
                    print('test')
                else:
                    target.user_id = request.user.id
                    target.view_count = 0
                    target.view_count_limit = 50 #とりあえずデフォルトを50回にしておく @ToDo ここは選べるようにするか？そうなると課金？
                    target.vuforia_target_id = response_content['target_id']


                # target = form.save(commit=False)

                target.save()

                ######## 一時ファイルを削除  @ToDo いずれ画像もs3にアップしてここで一時ファイルを削除する。
                delete_tmp_file(filePathTarget, metaPath, filePathContents)

                # if filePathTarget != None:
                #     default_storage.delete(filePathTarget)      #target(image)
                #
                # if metaPath != None:
                #     default_storage.delete(metaPath)            #meta
                #
                # if filePathContents != None:
                #     default_storage.delete(filePathContents)    #contents

                return redirect('hlar:target_list')
                # return render(request, 'hlar/target_edit.html', dict(msg='登録が完了しました。'))
        else:
            # Vuforia API エラー時
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_edit.html', dict(
                msg=response_content['result_code'],
                form = form,
                target_id = target_id,
                target = target,
                stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                buy_history = buy_history,
                s3_FQDN = s3_FQDN,
                TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
            ))



        # form = TargetForm(request.POST, instance=target)  # POST された request データからフォームを作成
        # if form.is_valid():    # フォームのバリデーション
        #     target = form.save(commit=False)
        #     target.save()
        #     return redirect('hlar:target_list')
    else:
        # GET 時
        form = TargetForm(instance=target)  # target インスタンスからフォームを作成

        if target.vuforia_target_id:
            vuforia_target = get_target_by_id(target.vuforia_target_id)
            target.name = vuforia_target['name']

        if target.target_link_URL == None:
            target.target_link_URL = ''

#    c = Context({"my_name": "Adrian"})
    # print('target.img_name')
    # print(target.img_name)

    # print("-----stripe_pulishable_key-----")
    # print(settings.STRIPE_PUBLISHABLE_KEY)

    return render(
        request,
        'hlar/target_edit.html',
        dict(
            form = form,
            target_id = target_id,
            target = target,
            stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
            buy_history = buy_history,
            s3_FQDN = s3_FQDN,
            TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
            CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
        ))



def target_temp_edit(request, target_id=None):

    targetFile = None

    # if request.user.is_authenticated() == False:
    #     return HttpResponseRedirect('/accounts/login/?next=%s' % request.path)

    msg = ''
    buy_history = 0

    target = Target()

    if request.method == 'POST':
        # POST 時

        ######## 入力チェック
        err = False
        errMsg = ''

        # ランダム文字列を作成
        n = 9
        random_str = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])

        #### 名前
        # if request.POST['target_name'] == '':
        #     # エラー
        #     err = True
        #     errMsg = '名前を入力して下さい。'
        # else:
        #     target.name = request.POST['target_name']

        target.name = random_str + '_temp'

        # #### 誘導リンク
        # target.target_link_URL = request.POST['target_link_URL']

        #### ターゲット @ToDo
        if err == False and request.FILES.get('target', False):

            ######## サイズチェックの前にresize処理
            targetFile = resize_img(request.FILES['target'])

            targetName = request.FILES['target'].name

            ## サイズチェック
            if targetFile and (targetFile.size > settings.TARGET_SIZE_LIMIT):
                # エラー
                err = True
                errMsg = 'ターゲット画像のサイズが制限({0}MB)を超えています。'.format(int(settings.TARGET_SIZE_LIMIT / 1000000))

            ## 拡張子チェック
            ext = os.path.splitext(targetName)[1].lower()

            if ext != '.jpeg' and ext != '.jpg':
                # エラー
                err = True
                errMsg = 'ターゲット画像のファイル形式が不正です。'

        #### コンテンツ
        if err == False and request.FILES.get('contents', False):
            contentsFile = request.FILES['contents']
            print('file_size')
            print(contentsFile.size)

            ## サイズチェック
            if contentsFile and (contentsFile.size > settings.CONTENTS_SIZE_LIMIT):
                # エラー
                err = True
                errMsg = 'コンテンツ動画のサイズが制限({0}MB)を超えています。'.format(int(settings.CONTENTS_SIZE_LIMIT / 1000000))

            ## 拡張子チェック
            ext = os.path.splitext(contentsFile.name)[1].lower()

            if ext != '.mp4' and ext != '.mov':
                # エラー
                err = True
                errMsg = 'コンテンツ動画のファイル形式が不正です。'


        if (request.FILES.keys() >= {'target'} and request.FILES.keys() >= {'contents'}) or \
            (request.FILES.keys() <= {'target'} and request.FILES.keys() <= {'contents'}):
            print('errなし')
        else:
            err = True
            errMsg = 'ターゲットとコンテンツは同時にアップして下さい。'

        if err:
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_temp_add.html', dict(
                err = err,
                msg= errMsg,
                # form = form,
                # target_id = target_id,
                target = target,
                # stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                # buy_history = buy_history,
                s3_FQDN = s3_FQDN,
                # TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                # CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
            ))


        ######## ターゲットファイル
        #### まず一時的にサーバーに保存
        # 保存パス(ファイル名含む)
        encTargetFile = None
        filePathTarget = None

        if request.FILES.keys() >= {'target'}:
            encTargetFileBase64 = base64.b64encode(targetFile.read())
            encTargetFile = encTargetFileBase64.decode('utf-8')

        # ######## 誘導先 リンク
        # target_link_URL = request.POST['target_link_URL']
        target_link_URL = ''

        # ######## ターゲット名
        target_name = target.name

        ######## meta テキスト
        #### テキスト作成
        encMetaFile = None
        metaPath = None
        # if request.FILES.keys() >= {'contents'} or request.POST['hid_content_name']:
        if request.FILES.keys() >= {'contents'} :

            content_name_for_meta = ''
            target_name_for_meta = ''
            if request.FILES.keys() >= {'contents'}:
                contentsFile = request.FILES['contents']
                content_name_for_meta = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)
                target_name_for_meta =  random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)
            elif request.POST['hid_content_name']:
                content_name_for_meta = request.POST['hid_content_name']
                target_name_for_meta = request.POST['target_file_name']

            # meta_file_name = targetFile.name.replace('.','') + '.txt'
            meta_file_name = target_name.replace('.','') + '.txt'
            metaPath = TARGET_FILE_PATH + meta_file_name

            metaContent = "{\n" \
                            '\t"title": "' + target_name + '",\n' \
                            '\t"url" : "' + s3_FQDN + content_name_for_meta + '",\n' \
                            '\t"linkUrl" : "' + target_link_URL + '",\n' \
                            '\t"targetImageUrl" : "' + s3_FQDN + target_name_for_meta + '"\n' \
                           '}'

            # ファイルが存在していれば削除
            if default_storage.exists(metaPath):
                default_storage.delete(metaPath)

            # ファイル保存
            default_storage.save(metaPath, ContentFile(metaContent))

            # file読み込み
            with open(metaPath, 'rb') as f:
                contents = f.read()

            # base64でencode
            encMetaFileBase64 = base64.b64encode(contents)
            encMetaFile = encMetaFileBase64.decode('utf-8')
            print("encMetaFile")
            print(encMetaFile)


        ######## Vuforia API で登録
        if target_id:
            # # target_id が指定されている (修正時)
            # data = {
            #     "name": target_name,
            #     # "width": 1,
            #     "width": 320,
            #     # "image": encTargetFile,
            #     # "application_metadata": encMetaFile,
            #     "active_flag": 1,
            # }
            #
            # if encTargetFile != None:
            #     data['image'] = encTargetFile
            #
            # if encMetaFile != None:
            #     data['application_metadata'] = encMetaFile
            #
            # response_content = update_target(target.vuforia_target_id, data)

            print('test')
        else:
            # target_id が指定されていない (追加時)
            response_content = add_target(max_num_results='',
                                     include_target_data=encMetaFile,
                                     image=encTargetFile,
                                     target_name=target_name)

        print('4444')
        print(response_content)

        if judge_vws_result(response_content['result_code']):
            filePathContents = None

            ######## Check for Duplicate Targets 同じターゲットが登録されていないか確認
            vuforia_target_id = ''
            if target_id:
                vuforia_target_id = target.vuforia_target_id
            else:
                vuforia_target_id = response_content['target_id']

            response_duplicate = duplicates(vuforia_target_id)
            print('response_duplicate')
            print(response_duplicate)

            if response_duplicate['result_code'] == 'Success' and len(response_duplicate['similar_targets']) > 0:
                #### 同じ画像が登録されている

                # バッチで実行
                proc = Popen("python manage.py deltarget '" + vuforia_target_id + "'",shell=True )

                # エラー時
                form = TargetForm(instance=target)  # target インスタンスからフォームを作成

                if target.vuforia_target_id:
                    vuforia_target = get_target_by_id(target.vuforia_target_id)
                    target.name = vuforia_target['name']

                # 一時ファイル削除
                delete_tmp_file(filePathTarget, metaPath, filePathContents)

                return render(request, 'hlar/target_temp_add.html', dict(
                    err = True,
                    msg = '類似画像がすでに登録されていた為、登録出来ませんでした。',
                    # form = form,
                    # target_id = target_id,
                    target = target,
                    # stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                    # buy_history = buy_history,
                    s3_FQDN = s3_FQDN,
                    # TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                    # CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
                ))


            else:
                ######## S3にコンテンツ(動画)を保存
                key_name = ''
                if request.FILES.keys() >= {'contents'}:

                    key_name = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)

                    #### S3にアップロード
                    client = boto3.client('s3')
                    transfer = S3Transfer(client)

                    # アップしたコンテンツを公開状態にする
                    s3 = boto3.resource('s3')
                    bucket = s3.Bucket(bucket_name)
                    bucket.upload_fileobj(contentsFile, key_name)

                    object_acl = s3.ObjectAcl(bucket_name, key_name)
                    response = object_acl.put(ACL='public-read')

                ######## S3にターゲット(image)を保存
                if request.FILES.keys() >= {'target'}:
                    key_name_target = random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)
                    if s3 == None:
                        s3 = boto3.resource('s3')

                    if bucket == None:
                        bucket = s3.Bucket(bucket_name)


                    print("targetFile.size")
                    print(targetFile.name)
                    print(targetFile.size)
                    targetFile.seek(0, 0)
                    bucket.upload_fileobj(targetFile, key_name_target)

                    object_acl = s3.ObjectAcl(bucket_name, key_name_target)
                    response = object_acl.put(ACL='public-read')


                ######## DBに登録
                if key_name != '':
                    target.content_name = key_name

                if request.FILES.keys() >= {'target'}:
                    target.img_name = random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)

                if target_link_URL:
                    target.target_link_URL = target_link_URL

                if target_id:   # target_id が指定されている (修正時)
                    print('test')
                else:
                    # target.user_id = request.user.id
                    target.view_count = 0
                    target.view_count_limit = 15 #とりあえずデフォルトを50回にしておく @ToDo ここは選べるようにするか？そうなると課金？
                    target.vuforia_target_id = response_content['target_id']

                target.save()

                ######## 一時ファイルを削除  @ToDo いずれ画像もs3にアップしてここで一時ファイルを削除する。
                delete_tmp_file(filePathTarget, metaPath, filePathContents)


                return render(
                    request,
                    'hlar/target_temp_add.html',
                    dict(
                        target = target,
                        s3_FQDN = s3_FQDN,
                    )
                )

                # return redirect('hlar:target_list')
        else:
            # Vuforia API エラー時
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_temp_add.html', dict(
                err = True,
                msg = response_content['result_code'],
                # form = form,
                # target_id = target_id,
                target = target,
                # stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
                # buy_history = buy_history,
                s3_FQDN = s3_FQDN,
                # TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
                # CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
            ))

    else:
        print('test')
        # # GET 時
        # form = TargetForm(instance=target)  # target インスタンスからフォームを作成
        #
        # if target.vuforia_target_id:
        #     vuforia_target = get_target_by_id(target.vuforia_target_id)
        #     target.name = vuforia_target['name']
        #
        # if target.target_link_URL == None:
        #     target.target_link_URL = ''

    return render(
        request,
        'hlar/target_temp_add.html',
        dict(
            # form = form,
            # target_id = target_id,
            target = target,
            # stripe_pulishable_key = settings.STRIPE_PUBLISHABLE_KEY,
            # buy_history = buy_history,
            s3_FQDN = s3_FQDN,
            # TARGET_SIZE_LIMIT = format(int(settings.TARGET_SIZE_LIMIT / 1000000)),
            # CONTENTS_SIZE_LIMIT = format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)),
        ))

def target_del(request, target_id):

    if target_id:   # target_id が指定されている
        target = get_object_or_404(Target, pk=target_id)
        # pprint(vars(target))
    else:         # target_id が指定されていない
        return HttpResponse('エラー')

    print('target.vuforia_target_id')
    print(target.vuforia_target_id)

    ret = del_target_func(target)

    # ######## Vuforia のデータをAPIで削除
    # response_content = del_target(target.vuforia_target_id)
    #
    # print('response_content')
    # print(response_content)
    #
    # ######## HLAR側 DB Target.del_flg を onにする
    # try:
    #     target.del_flg = True
    #     target.save()
    # except Exception as e:
    #     print ('=== エラー内容 ===')
    #     print ('type:' + str(type(e)))
    #     print ('args:' + str(e.args))
    #     print ('message:' + e.message)
    #     print ('e自身:' + str(e))
    #
    # ######## S3のデータを削除
    # #### コンテンツ動画
    # client = boto3.client('s3')
    # response = client.delete_object(
    #     Bucket = bucket_name,
    #     Key = target.content_name
    # )
    #
    # #### ターゲット画像
    # response = client.delete_object(
    #     Bucket = bucket_name,
    #     Key = target.img_name
    # )
    #
    #
    # if judge_vws_result(response_content['result_code']):
    #     return redirect('hlar:target_list')
    # else:
    #     return render(request, 'hlar/target_edit.html', dict(msg=response_content['result_code']))

    print('ret del')
    print(ret)
    # pprint(vars(ret))


    if ret['ret'] == True:
        return redirect('hlar:target_list')
    else:
        return render(request, 'hlar/target_edit.html', dict(msg=ret['msg']))

    # return HttpResponse('ターゲットの削除')


def target_upload(request):
    targetFile = request.FILES['target']

    # 保存パス(ファイル名含む)
    filePath = TARGET_FILE_PATH + targetFile.name

    print("filePath")
    print(filePath)

    # ファイルが存在していれば削除
    if default_storage.exists(filePath):
        default_storage.delete(filePath)

    # ファイルを保存
    path = default_storage.save(filePath, ContentFile(targetFile.read()))

    print("path")
    print(path)

    dictData = {'filename':targetFile.name, "filelength":82}
    return HttpResponse(json.dumps(dictData))

def target_payment(request):
    # print('target_payment----1------')
    # print(request.POST)
    # pprint(vars(request))

    print(request.POST['targetId'])
    print(request.POST['amount'])
    print(request.POST['tokenId'])

    ######## STRIPE の処理

    # Set your secret key: remember to change this to your live secret key in production
    # See your keys here: https://dashboard.stripe.com/account/apikeys
    # stripe.api_key = "sk_test_TwoBPzByKz7FZ35aoeBlbuTl"
    # stripe.api_key = "sk_test_Po5fLfcGq5FnakXbyvB7IIO9"
    stripe.api_key = settings.STRIPE_API_KEY


    # Token is created using Stripe.js or Checkout!
    # Get the payment token ID submitted by the form:
    #token = request.form['stripeToken'] # Using Flask

    # Charge the user's card:
    try:
        charge = stripe.Charge.create(
            amount=request.POST['amount'],
            currency="jpy",
            description="Example charge",
            source=request.POST['tokenId'],
        )
    except stripe.error.CardError as e:
        dictData = {'ret':False, 'msg': '決済処理の途中でエラーが発生しました。'}
        return HttpResponse(json.dumps(dictData))

    # print('----charge----')
    # print(charge.amount)
    # print(charge['_previous']['amount'])
    # pprint(vars(charge))


    ######## hlarのDBへINSERT
    payment = Payment()
    payment.user_id = request.user.id
    payment.target_id = request.POST['targetId']
    payment.amount = request.POST['amount']
    payment.brought_view_count = request.POST['broughtViewCount']
    payment.token_id = request.POST['tokenId']

    payment.save()


    ######## target.view_count_limit を増やす
    # 2980/29800 の所定の金額以外では処理しない。
    target = get_object_or_404(Target, pk=request.POST['targetId'])

    if charge.amount == 2980 or charge.amount == 29800:
        print("-----target.save------")
        target.view_count_limit = int(target.view_count_limit) + int(request.POST['broughtViewCount'])
        print(target.view_count_limit)
        target.save()

        ######## vuforia の targetをactiveにする。
        data = {"active_flag": 1}
        print("vuforia active")
        print(target.vuforia_target_id)
        update_target(target.vuforia_target_id, data)

        dictData = {'ret':True}
        return HttpResponse(json.dumps(dictData))
    else:
        dictData = {'ret':False, 'msg': '金額でエラーが発生しました。'}
        return HttpResponse(json.dumps(dictData))



    # targetFile = request.FILES['target']
    #
    # # 保存パス(ファイル名含む)
    # filePath = TARGET_FILE_PATH + targetFile.name
    #
    # print("filePath")
    # print(filePath)
    #
    # # ファイルが存在していれば削除
    # if default_storage.exists(filePath):
    #     default_storage.delete(filePath)
    #
    # # ファイルを保存
    # path = default_storage.save(filePath, ContentFile(targetFile.read()))
    #
    # print("path")
    # print(path)
    #
    # dictData = {'filename':targetFile.name, "filelength":82}
    # return HttpResponse(json.dumps(dictData))


# def twitter_login(request):
#
#     # Create your consumer with the proper key/secret.
#     consumer = oauth.Consumer(key=consumer_key,
#         secret=consumer_secret)
#
#     # Request token URL for Twitter.
#     request_token_url = "https://api.twitter.com/oauth/request_token"
#
#     # Create our client.
#     client = oauth.Client(consumer)
#
#     # The OAuth Client request works just like httplib2 for the most part.
#     resp, content = client.request(request_token_url, "GET")
#
#     content_str = content.decode('utf-8')
#
#     request_token = dict(parse_qsl(content_str))
#
#     url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])
#
#     #### request_token と request_token_secret を保存
#     # DBに保存
#     # oauth_obj = OauthTbl()
#     # oauth_obj.oauth_token = request_token['oauth_token']
#     # oauth_obj.oauth_token_secret = request_token['oauth_token_secret']
#     # oauth_obj.save()
#
#     # sessionに保存
#     request.session['oauth_token'] = request_token['oauth_token']
#     request.session['oauth_token_secret'] = request_token['oauth_token_secret']
#
#
#     return HttpResponseRedirect(url)
#
#
#
#
#
#
#     # print(content.split('&'))
#     # request_token = dict(parse_qsl(content))
#
#     # 認証ページに遷移
#     # url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])
#     # url = 'http://twitter.com/oauth/authenticate?oauth_token=2UsavwAAAAAA1SEBAAABXOcW3d0'
#     # print('<meta http-equiv="refresh"content="1; url=%s">' % url)
#
#     # return HttpResponseRedirect(url)
#
#     # # consumer = oauth2.Consumer
#     # # print(consumer)
#     # consumer = oauth2.Consumer(key=consumer_key, secret=consumer_secret)
#     # client = oauth2.Client(consumer)
#     # # reqest_token を取得
#     # resp, content = client.request(request_token_url, 'GET')
#     #
#     # print(content)
#     #
#     # request_token = dict(parse_qsl(content))
#     #
#     # # 認証ページに遷移
#     # url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])
#     # print('<meta http-equiv="refresh"content="1; url=%s">' % url)
#     #
#     # # request_token と request_token_secret を保存
#     # con = sqlite3.connect('oauth.db')
#     # con.execute(u'insert into oauth values (?, ?)', (request_token['oauth_token'], request_token['oauth_token_secret']))
#     # con.commit()
#     # con.close()

def parse_qsl(url):
    param = {}
    for i in url.split('&'):
        _p = i.split('=')
        param.update({_p[0]: _p[1]})
    return param

def delete_tmp_file(filePathTarget, metaPath, filePathContents):
    if filePathTarget != None:
        default_storage.delete(filePathTarget)      #target(image)

    if metaPath != None:
        default_storage.delete(metaPath)            #meta

    if filePathContents != None:
        default_storage.delete(filePathContents)    #contents

# 画像をリサイズする
def resize_img(imgFile):

    #### resize処理(widthを500pxとしてheightを計算)
    targetFile = Image.open(imgFile)

    if hasattr(targetFile._getexif(), "items" ):

        exif = dict((ExifTags.TAGS[k], v) for k, v in targetFile._getexif().items() if k in ExifTags.TAGS)

        print("exif")
        print(exif)

        if "Orientation" in exif:
            # if not exif['Orientation']:
            if exif['Orientation']:
                if exif['Orientation'] == 6:
                    targetFile = targetFile.rotate(-90, expand=True)


    (width, height) = targetFile.size
    height_calc = int((height * 500) / width)

    size = ( 500, height_calc)
    thumb = targetFile.resize(size, Image.ANTIALIAS)

    #### 上記　thumb はImage objectなのでdjangoのFile Object-likeなものに変換。
    thumb_io = BytesIO()
    thumb.save(thumb_io, format='JPEG')

    targetFile = ContentFile(thumb_io.getvalue())   #djangoのfile object-likeなものに変換。

    return targetFile


#ターゲット削除
def del_target_func(target):
    ######## Vuforia のデータをAPIで削除
    response_content = del_target(target.vuforia_target_id)

    print('response_content')
    print(response_content)

    if response_content['result_code'] != 'UnknownTarget' and judge_vws_result(response_content['result_code']):
        # return dict(ret=True)
        print("ok")
    else:
        return dict(ret=False, msg=response_content['result_code'])

    ######## HLAR側 DB Target.del_flg を onにする
    try:
        target.del_flg = True
        target.save()
    except Exception as e:
        print ('=== エラー内容 ===')
        print ('type:' + str(type(e)))
        print ('args:' + str(e.args))
        print ('message:' + e.message)
        print ('e自身:' + str(e))
        return dict(ret=False, msg=e.message)

    ######## S3のデータを削除
    #### コンテンツ動画
    client = boto3.client('s3')
    response = client.delete_object(
        Bucket = bucket_name,
        Key = target.content_name
    )

    #### ターゲット画像
    response = client.delete_object(
        Bucket = bucket_name,
        Key = target.img_name
    )


    return dict(ret=True)
    # if judge_vws_result(response_content['result_code']):
    #     return dict(ret=True)
    # else:
    #     return dict(ret=False, msg=response_content['result_code'])




## ListViewを使う方法
# class IndexView(generic.ListView):
#     template_name = 'hlar/index.html'   # これは hlar/templates/hlar/index.html
#     context_object_name = 'latest_target_list'    #これをやらないと'question_list'というデフォルトの名前でtemplateに渡される。
#
#     def get_queryset(self):
#
#         """
#         Return the last five published questions (not including those set to be
#         published in the future).
#         """
#         return Target.objects.all()


# def index(request):
#     return HttpResponse("Hello, world. You're at the polls index.")

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class TargetViewSet(viewsets.ModelViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer

    def list(self, request):
        # print('asdf')
        # print(self)
        # print(request)
        queryset = Target.objects.all()
        serializer = TargetSerializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):

        print('pk')
        print(pk)

        queryset = Target.objects.all()
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))

        pprint(vars(target_object))
        serializer = TargetSerializer(target_object)
        return Response(serializer.data)

        # queryset = Target.objects.all()
        # target = get_object_or_404(queryset, pk=pk)
        # serializer = TargetSerializer(target)
        # return Response(serializer.data)


    @detail_route(methods=['post'])
    def set_count_up_and_inactive(self, request, pk=None):

        queryset = Target.objects.all()

        # targetを取得
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))

        # カウントアップしてセット
        now_count = target_object.view_count + 1
        target_object.view_count = now_count

        print('now_count')
        print(now_count)

        # 保存
        target_object.save()

        # リミット回数に達していたらvuforiaのtargetをinactiveにする
        if target_object.view_count_limit <= now_count:
            print('start inactive vuforia')
            data = {"active_flag": 0}
            update_target(str(pk), data)
        else:
            print('still active vuforia')

        # pprint(vars(target_object))
        print(target_object.view_count)


        serializer = TargetSerializer(target_object)
        return Response(serializer.data)


    @detail_route(methods=['post'])
    def ins_access_log(self, request, pk=None):

        ui = request.GET.get(key="ui", default="")
        os = request.GET.get(key="os", default="")

        print("------ui---------")
        print(ui)

        queryset = Target.objects.all()

        # targetを取得
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))

        access_log_entity = AccessLog()
        access_log_entity.target_id = target_object.id
        access_log_entity.operating_system = os
        access_log_entity.device_unique_identifier = ui


        # validation
        try:
            # user.full_clean()
            access_log_entity.clean()

            # save
            access_log_entity.save()

        except ValidationError as e:
            # non_field_errors = e.message_dict[NON_FIELD_ERRORS]
            pprint(vars(e))
            print(e.message)
            msg['error_msg'] = e.message

        serializer = AccessLogSerializer(access_log_entity)
        return Response(serializer.data)





        # # カウントアップしてセット
        # now_count = target_object.view_count + 1
        # target_object.view_count = now_count
        #
        # print('now_count')
        # print(now_count)
        #
        # # 保存
        # target_object.save()
        #
        # # リミット回数に達していたらvuforiaのtargetをinactiveにする
        # if target_object.view_count_limit <= now_count:
        #     print('start inactive vuforia')
        #     data = {"active_flag": 0}
        #     update_target(str(pk), data)
        # else:
        #     print('still active vuforia')
        #
        # # pprint(vars(target_object))
        # print(target_object.view_count)
        #
        #
        # serializer = TargetSerializer(target_object)
        # return Response(serializer.data)





        # user = self.get_object()
        # serializer = PasswordSerializer(data=request.data)
        # if serializer.is_valid():
        #     user.set_password(serializer.data['password'])
        #     user.save()
        #     return Response({'status': 'password set'})
        # else:
        #     return Response(serializer.errors,
        #                     status=status.HTTP_400_BAD_REQUEST)




# package のoverrideテスト(これで一応 こっちが実行されるがtransaction がundefinedなどエラーが出るのでコメントアウト)
# @classmethod
# def create_user(cls, *args, **kwargs):
#
#     print('override!!!!')
#
#     username_field = cls.username_field()
#     if 'username' in kwargs and username_field not in kwargs:
#         kwargs[username_field] = kwargs.pop('username')
#     try:
#         if hasattr(transaction, 'atomic'):
#             # In Django versions that have an "atomic" transaction decorator / context
#             # manager, there's a transaction wrapped around this call.
#             # If the create fails below due to an IntegrityError, ensure that the transaction
#             # stays undamaged by wrapping the create in an atomic.
#             with transaction.atomic():
#                 user = cls.user_model().objects.create_user(*args, **kwargs)
#         else:
#             user = cls.user_model().objects.create_user(*args, **kwargs)
#     except IntegrityError:
#         # User might have been created on a different thread, try and find them.
#         # If we don't, re-raise the IntegrityError.
#         exc_info = sys.exc_info()
#         # If email comes in as None it won't get found in the get
#         if kwargs.get('email', True) is None:
#             kwargs['email'] = ''
#         try:
#             user = cls.user_model().objects.get(*args, **kwargs)
#         except cls.user_model().DoesNotExist:
#             six.reraise(*exc_info)
#     return user
# #これでoverrideを紐付ける。(これが無いoverirdeされない)
# social_django.storage.DjangoUserMixin.create_user = create_user



class UserProfileRegistration(RegistrationView):
    success_url = '/hlar'
    form_class = RegistrationForm

    def register(self, form):
        """
        Implement user-registration logic here.

        """
        # # UserModel = User()
        # user = User.objects.create_user(
        #     username = form.cleaned_data['username'],
        #     # first_name = form.cleaned_data['first_name'],
        #     # last_name = form.cleaned_data['last_name'],
        #     email=form.cleaned_data['email'],
        #     password=form.cleaned_data['password1']
        # )

        """
        Given a username, email address and password, register a new
        user account, which will initially be inactive.
        Along with the new ``User`` object, a new
        ``registration.models.RegistrationProfile`` will be created,
        tied to that ``User``, containing the activation key which
        will be used for this account.
        An email will be sent to the supplied email address; this
        email should contain an activation link. The email will be
        rendered using two templates. See the documentation for
        ``RegistrationProfile.send_activation_email()`` for
        information about these templates and the contexts provided to
        them.
        After the ``User`` and ``RegistrationProfile`` are created and
        the activation email is sent, the signal
        ``registration.signals.user_registered`` will be sent, with
        the new ``User`` as the keyword argument ``user`` and the
        class of this backend as the sender.
        """
        site = get_current_site(self.request)

        if hasattr(form, 'save'):
            new_user_instance = form.save()
        else:
            new_user_instance = (UserModel().objects
                                 .create_user(**form.cleaned_data))

        new_user = self.registration_profile.objects.create_inactive_user(
            new_user=new_user_instance,
            site=site,
            send_email=self.SEND_ACTIVATION_EMAIL,
            request=self.request,
        )
        signals.user_registered.send(sender=self.__class__,
                                     user=new_user,
                                     request=self.request)
        return new_user
