import os
import json
import base64
import subprocess
from collections import OrderedDict
from subprocess import Popen

from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.template import loader
from django.views import generic
from django.utils import timezone

from django.http import Http404

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
import urllib.parse
# import twitter
from requests_oauthlib import OAuth1Session

# DB登録時のバリデーション
from django.core.exceptions import ValidationError

# ログイン状態を判別する為に必要
from django.contrib.auth.decorators import login_required

# signup
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
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

# 画像のリサイズに使用
from PIL import Image
from io import BytesIO
from django.core.files.base import ContentFile
from PIL import ExifTags

# CSRFを無効化する
from django.views.decorators.csrf import csrf_exempt

import re

TARGET_FILE_PATH = './static/images/'

bucket_name = settings.S3_BUCKET_NAME
s3_FQDN = 'https://' + bucket_name + '.s3.amazonaws.com/'


def hlar_top(request):
    current_site = get_current_site(request)
    print(current_site.domain)

    if request.user.is_authenticated() == False:
        try:
            # oauth で返ってきた時はsessionにid が入っているのでそれを取得する。
            user = User.objects.filter(id=request.session._session_cache['_auth_user_id'])[0]

            user_auth = authenticate(username=user.email, password=DEFAULT_PASS)
            login(request, user_auth)

        except Exception as e:
            print('error')

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
        form = SignUpForm(request.POST)

        if form.is_valid():

            form.save()

            user_obj = User.objects.filter(email=form.cleaned_data.get('email'))[0]
            password = user_obj.password

            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')

            user = authenticate(username=form.cleaned_data.get('email'), password=raw_password)
            login(request, user)
            return HttpResponseRedirect('/hlar')
    else:
        form = SignUpForm()
    return render(request, 'hlar/signup.html', {'form': form})


def hlar_user_manage(request):

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

    content_str = content.decode('utf-8')
    access_token = dict(parse_qsl(content_str))

    return access_token['oauth_token'], access_token['oauth_token_secret']


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
            user_entity.clean()

            # save
            user_entity.save()

            # 認証メール 送信 @ToDo

            msg['success_msg'] = 'ユーザー登録が完了しました。'

        except ValidationError as e:
            msg['error_msg'] = e.message

    user = {}

    if 'user_entity' in locals():
        user['mail'] = user_entity.mail
        user['name'] = user_entity.name
        user['oauth_id'] = user_entity.oauth_id

    elif 'user_info' in request.session:
        user['oauth_id'] = request.session['user_info']['oauth_id']
        user['name'] = request.session['user_info']['name']

    return render(request,
                  'hlar/user_form.html',  # 使用するテンプレート
                  {'user': user, 'msg': msg})         # テンプレートに渡すデータ


def user_edit(request, user_id=None):

    msg = {}

    if request.method == "POST":
        mode = request.POST["mode"]

        if mode == 'add':
            form = UserForm(data=request.POST)  # ← 受け取ったPOSTデータを渡す
        elif mode == 'edit':
            user = get_object_or_404(User, pk=user_id)
            form = UserForm(request.POST or None, instance=user)

        if form.is_valid():  # ← 受け取ったデータの正当性確認

            if mode == 'add':
                form.save()
                msg['success_msg'] = '更新が完了しました。'

            elif mode == 'edit':

                if request.POST.get('password', False):
                    user.set_password(request.POST['password'])

                form = form.save()

                if request.POST.get('password', False):
                    messages.success(request, 'パスワードを変更したので改めてログインして下さい。')

                    return HttpResponseRedirect('/login')
                else:
                    msg['success_msg'] = '更新が完了しました。'

                user = get_object_or_404(User, pk=user_id)
                form = UserForm(instance=user)  # target インスタンスからフォームを作成
        else:
            print('save_error')
            pass
    else:         # target_id が指定されていない (追加時)
        if user_id:   # target_id が指定されている (修正時)
            user = get_object_or_404(User, pk=user_id)
        else:
            user = User()
        form = UserForm(instance=user)  # target インスタンスからフォームを作成

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


@login_required
def target_list(request):

    if request.user.is_authenticated() == False:
        return HttpResponseRedirect('/accounts/login/?next=%s' % request.path)

    ua = parse_ua(request.META['HTTP_USER_AGENT'])

    # ターゲット一覧を取得
    targets = Target.objects.filter(user_id=str(request.user.id), del_flg=False)

    addTarget = True
    if len(targets) >= settings.TARGET_LIMIT_COUNT:
        addTarget = False

    for target in targets:
        # シェアのリンクを作成
        arrContentName = target.img_name.split(".")
        targetImgURL = settings.URL_ROOT + "hlar/target/preview_img/" + arrContentName[0]

        # Twitter
        twitterText = _("ARアプリ【UNIVERSE.AR】でこの画像を読み取ってみましょう！ #universear")
        twitterParam = { 'text' : twitterText, 'url' : targetImgURL}
        target.twitter_url = 'https://twitter.com/share?' + urllib.parse.urlencode(twitterParam)

        # facebook
        facebookParam = { 'u' : targetImgURL}
        target.fb_url = 'https://www.facebook.com/share.php?' + urllib.parse.urlencode(facebookParam)

    return render(request,
                  'hlar/target_list.html',     # 使用するテンプレート
                  {'targets': targets,
                   's3_FQDN': s3_FQDN,
                   'is_mobile': ua.is_mobile,
                   'addTarget': addTarget,
                   'TARGET_LIMIT_COUNT': settings.TARGET_LIMIT_COUNT,
                  })         # テンプレートに渡すデータ


# img_name は拡張子は無い状態
def target_preview_img(request, img_name=None):

    target = None

    if len(img_name) < 9:
        raise Http404

    if img_name:
        targets_object = Target.objects.filter(img_name__contains=img_name)

    if len(targets_object) == 0:
        raise Http404

    for t in targets_object:
        target = t

    return render(
        request,
        'hlar/target_preview.html',
        dict(
            target = target,
            s3_FQDN = s3_FQDN,
            sm_image = target.img_name,
        ))


def target_edit(request, target_id=None):

    targetFile = None

    if request.user.is_authenticated() == False:
        return HttpResponseRedirect('/accounts/login/?next=%s' % request.path)

    msg = ''
    buy_history = 0

    if target_id:   # target_id が指定されている (修正時)
        target = get_object_or_404(Target, pk=target_id)

        # 300回の購入履歴があるか確認
        payments_object = Payment.objects.filter(target_id=str(target_id), brought_view_count=300)

        buy_history = len(payments_object)
    else:         # target_id が指定されていない (追加時)
        #### 登録がMAX数に達していたら一覧に飛ばす
        # ターゲット一覧を取得
        targets = Target.objects.filter(user_id=str(request.user.id), del_flg=False)

        if len(targets) >= settings.TARGET_LIMIT_COUNT:
            return redirect('hlar:target_list')

        target = Target()


    if request.method == 'POST':
        # POST 時

        try:
            ######## 入力チェック
            err = False
            errMsg = ''

            #### 名前
            if request.POST['target_name'] == '':
                # エラー
                raise Exception('名前を入力して下さい。')
            else:
                target.name = request.POST['target_name']
                target.target_name = request.POST['target_name']

            #### 誘導リンク
            target.target_link_URL = request.POST['target_link_URL']

            #### コンテンツ
            if request.FILES.get('contents', False):
                contentsFile = request.FILES['contents']

                ## サイズチェック
                if contentsFile and (contentsFile.size > settings.CONTENTS_SIZE_LIMIT):
                    # エラー
                    raise Exception('コンテンツ動画のサイズが制限({0}MB)を超えています。'.format(int(settings.CONTENTS_SIZE_LIMIT / 1000000)))

                ## 拡張子チェック
                ext = os.path.splitext(contentsFile.name)[1].lower()

                if ext != '.mp4' and ext != '.mov':
                    # エラー
                    raise Exception('コンテンツ動画のファイル形式が不正です。')

            #### ターゲット @ToDo
            if request.FILES.get('target', False):
                ## 拡張子チェック
                targetName = request.FILES['target'].name
                ext = os.path.splitext(targetName)[1].lower()

                if ext != '.jpeg' and ext != '.jpg':
                    # エラー
                    raise Exception('ターゲット画像のファイル形式が不正です。')

                ## ターゲット画像をresize
                targetFile = resize_img(request.FILES['target'])

                ## サイズチェック
                if targetFile and (targetFile.size > settings.TARGET_SIZE_LIMIT):
                    # エラー
                    raise Exception('ターゲット画像のサイズが制限({0}MB)を超えています。'.format(int(settings.TARGET_SIZE_LIMIT / 1000000)))

            if (request.FILES.keys() >= {'target'} and request.FILES.keys() >= {'contents'}) or \
                (request.FILES.keys() <= {'target'} and request.FILES.keys() <= {'contents'}):
                print('errなし')
            else:
                err = True
                # errMsg = 'ターゲットとコンテンツは同時にアップして下さい。'
                raise Exception('ターゲットとコンテンツは同時にアップして下さい。')

        except Exception as e:
            # if err:
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_edit.html', dict(
                msg= e.args[0],
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
            # base64でencode
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

                content_name_for_meta = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)
                target_name_for_meta =  random_str + '_' + re.sub('[^\x01-\x7E]','', targetName)


            elif request.POST['hid_content_name']:
                content_name_for_meta = request.POST['hid_content_name']
                target_name_for_meta = request.POST['target_file_name']

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

        if judge_vws_result(response_content['result_code']):
            filePathContents = None

            ######## Check for Duplicate Targets 同じターゲットが登録されていないか確認
            vuforia_target_id = ''
            if target_id:
                vuforia_target_id = target.vuforia_target_id
            else:
                vuforia_target_id = response_content['target_id']

            response_duplicate = duplicates(vuforia_target_id)

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

                    key_name = random_str + '_' + re.sub('[^\x01-\x7E]','', contentsFile.name)

                    print("key_name")
                    print(key_name)

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

                target.save()

                ######## 一時ファイルを削除  @ToDo いずれ画像もs3にアップしてここで一時ファイルを削除する。
                delete_tmp_file(filePathTarget, metaPath, filePathContents)

                return redirect('hlar:target_list')
        else:
            # Vuforia API エラー時
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            print("vuforia error")

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
    else:
        # GET 時
        form = TargetForm(instance=target)  # target インスタンスからフォームを作成

        if target.target_link_URL == None:
            target.target_link_URL = ''

        if target.target_name == None:
            target.target_name = ''


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

        target.name = random_str + '_temp'
        target.target_name = random_str + '_temp'

        #### ターゲット @ToDo
        if err == False and request.FILES.get('target', False):

            ## 拡張子チェック
            targetName = request.FILES['target'].name
            ext = os.path.splitext(targetName)[1].lower()

            if ext != '.jpeg' and ext != '.jpg':
                # エラー
                err = True
                errMsg = 'ターゲット画像のファイル形式が不正です。'
            else:
                ######## サイズチェックの前にresize処理
                targetFile = resize_img(request.FILES['target'])

                ## サイズチェック
                if targetFile and (targetFile.size > settings.TARGET_SIZE_LIMIT):
                    # エラー
                    err = True
                    errMsg = 'ターゲット画像のサイズが制限({0}MB)を超えています。'.format(int(settings.TARGET_SIZE_LIMIT / 1000000))

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
                target = target,
                s3_FQDN = s3_FQDN,
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
        target_link_URL = ''

        # ######## ターゲット名
        target_name = target.name

        ######## meta テキスト
        #### テキスト作成
        encMetaFile = None
        metaPath = None
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


        ######## Vuforia API で登録
        if target_id:
            print('test')
        else:
            # target_id が指定されていない (追加時)
            response_content = add_target(max_num_results='',
                                     include_target_data=encMetaFile,
                                     image=encTargetFile,
                                     target_name=target_name)

        if judge_vws_result(response_content['result_code']):
            filePathContents = None

            ######## Check for Duplicate Targets 同じターゲットが登録されていないか確認
            vuforia_target_id = ''
            if target_id:
                vuforia_target_id = target.vuforia_target_id
            else:
                vuforia_target_id = response_content['target_id']

            response_duplicate = duplicates(vuforia_target_id)

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
                    target = target,
                    s3_FQDN = s3_FQDN,
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

        else:
            # Vuforia API エラー時
            form = TargetForm(instance=target)  # target インスタンスからフォームを作成

            print("Vuforia error")

            if target.vuforia_target_id:
                vuforia_target = get_target_by_id(target.vuforia_target_id)
                target.name = vuforia_target['name']

            return render(request, 'hlar/target_temp_add.html', dict(
                err = True,
                msg = response_content['result_code'],
                target = target,
                s3_FQDN = s3_FQDN,
            ))

    else:
        print('test')
        # # GET 時

    return render(
        request,
        'hlar/target_temp_add.html',
        dict(
            target = target,
            s3_FQDN = s3_FQDN,
        ))

def target_del(request, target_id):

    if target_id:   # target_id が指定されている
        target = get_object_or_404(Target, pk=target_id)
        # pprint(vars(target))
    else:         # target_id が指定されていない
        return HttpResponse('エラー')

    ret = del_target_func(target)

    if ret['ret'] == True:
        return redirect('hlar:target_list')
    else:
        return render(request, 'hlar/target_edit.html', dict(msg=ret['msg']))

def beta_monitor(request):
    return render(request, 'hlar/beta_monitor.html')

def target_upload(request):
    targetFile = request.FILES['target']

    # 保存パス(ファイル名含む)
    filePath = TARGET_FILE_PATH + targetFile.name

    # ファイルが存在していれば削除
    if default_storage.exists(filePath):
        default_storage.delete(filePath)

    # ファイルを保存
    path = default_storage.save(filePath, ContentFile(targetFile.read()))

    dictData = {'filename':targetFile.name, "filelength":82}
    return HttpResponse(json.dumps(dictData))

def target_payment(request):

    ######## STRIPE の処理
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
        target.view_count_limit = int(target.view_count_limit) + int(request.POST['broughtViewCount'])
        target.save()

        ######## vuforia の targetをactiveにする。
        data = {"active_flag": 1}
        update_target(target.vuforia_target_id, data)

        dictData = {'ret':True}
        return HttpResponse(json.dumps(dictData))
    else:
        dictData = {'ret':False, 'msg': '金額でエラーが発生しました。'}
        return HttpResponse(json.dumps(dictData))


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

# # 動画をリサイズする
# def resize_video(path):
#
#     clip = VideoFileClip(path)
#     clip = clip.rotate(90)
#     # clip = clip.crop(x_center=540, y_center=960, width=1080, height=608)
#     # clip = clip.resize(width=500)
#
#     return clip
#
#     #
#     # rotation = get_rotation(file_path)
#     # if rotation == 90:  # If video is in portrait
#     #     clip = vfx.rotate(clip, -90)
#     # elif rotation == 270:  # Moviepy can only cope with 90, -90, and 180 degree turns
#     #     clip = vfx.rotate(clip, 90)  # Moviepy can only cope with 90, -90, and 180 degree turns
#     # elif rotation == 180:
#     #     clip = vfx.rotate(clip, 180)
#     #
#     # clip = clip.resize(height=720)  # You may want this line, but it is not necessary
#     # return clip


#ターゲット削除
def del_target_func(target):
    ######## Vuforia のデータをAPIで削除
    response_content = del_target(target.vuforia_target_id)

    print('response_content')
    print(response_content)

    if response_content['result_code'] != 'UnknownTarget' and judge_vws_result(response_content['result_code']):
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


######## WEB API
@csrf_exempt
def file_upload_api(request):

    param = "aaa"
    data = OrderedDict([ ('test', param) ])
    return render_json_response(request, data)



def render_json_response(request, data, status=None):
    """response を JSON で返却"""
    json_str = json.dumps(data, ensure_ascii=False, indent=2)
    callback = request.GET.get('callback')
    if not callback:
        callback = request.POST.get('callback')  # POSTでJSONPの場合
    if callback:
        json_str = "%s(%s)" % (callback, json_str)
        response = HttpResponse(json_str, content_type='application/javascript; charset=UTF-8', status=status)
    else:
        response = HttpResponse(json_str, content_type='application/json; charset=UTF-8', status=status)
    return response


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class TargetViewSet(viewsets.ModelViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer

    def list(self, request):
        queryset = Target.objects.all()
        serializer = TargetSerializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        queryset = Target.objects.all()
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))
        serializer = TargetSerializer(target_object)
        return Response(serializer.data)


    @detail_route(methods=['post'])
    def set_count_up_and_inactive(self, request, pk=None):

        queryset = Target.objects.all()

        # targetを取得
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))

        # カウントアップしてセット
        now_count = target_object.view_count + 1
        target_object.view_count = now_count

        # 保存
        target_object.save()

        # リミット回数に達していたらvuforiaのtargetをinactiveにする
        if target_object.view_count_limit <= now_count:
            print('start inactive vuforia')
            data = {"active_flag": 0}
            update_target(str(pk), data)
        else:
            print('still active vuforia')

        serializer = TargetSerializer(target_object)
        return Response(serializer.data)


    @detail_route(methods=['post'])
    def ins_access_log(self, request, pk=None):

        ui = request.GET.get(key="ui", default="")
        os = request.GET.get(key="os", default="")
        queryset = Target.objects.all()

        # targetを取得
        target_object = get_object_or_404(queryset, vuforia_target_id=str(pk))

        access_log_entity = AccessLog()
        access_log_entity.target_id = target_object.id
        access_log_entity.operating_system = os
        access_log_entity.device_unique_identifier = ui

        # validation
        try:
            access_log_entity.clean()

            # save
            access_log_entity.save()

        except ValidationError as e:
            pprint(vars(e))
            print(e.message)
            msg['error_msg'] = e.message

        serializer = AccessLogSerializer(access_log_entity)
        return Response(serializer.data)

    @detail_route(methods=['post'])
    def file_upload(self, request, pk=None):

        file_obj = request.FILES['file']
        return Response(null)


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
