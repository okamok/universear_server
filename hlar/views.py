import os
import json
import base64

from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.template import loader
from django.views import generic
from django.utils import timezone

from pprint import pprint

from hlar.models import User, Target, Oauth as OauthTbl
from django.db.models import Count
from hlar.forms import TargetForm, UserForm
from hlar.vuforiaAPI import add_target, get_targets, get_targets_user_id, judge_vws_result, get_target_id_from_name, update_target
from hlar.twitterAPI import get_twitter_account


import oauth2 as oauth
import django_filters
from rest_framework import viewsets, filters
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response
from hlar.serializer import UserSerializer, TargetSerializer

# from boto3.s3.key import Key
# from boto3.s3.connection import S3Connection
import boto3

import urllib
import twitter
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


S3_USER = 's3user'
S3_ACCESS_KEY = 'AKIAJYYCJVHFIZK4Q6ZQ'
S3_SECRET_KEY = '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'

SERVER_ACCESS_KEYS = '6968bbd6779ed68181552a8449c786bf85bfe650'
SERVER_SECRET_KEYS = '5a244dbd3afd62b6808b65a55b3a9a63187e543b'
# TARGET_FILE_PATH = './tmp/'
TARGET_FILE_PATH = './static/images/'


# oauth 関連
request_token_url = 'http://twitter.com/oauth/request_token'
# access_token_url = 'http://twitter.com/oauth/access_token'
access_token_url = 'https://twitter.com/oauth/access_token'


authenticate_url = 'http://twitter.com/oauth/authenticate'



consumer_key = '05WxUGIG4paZZZWj22cZJR6qC'
consumer_secret = 'zodNRE2HNnaOQyQAzMyg9xPdA7UunVcVdXkElkTO4NaAwQYxya'



def hlar_top(request):

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
    print('aaaaaa')
    # pprint(vars(user))
    # print(type(user))
    #

    if request.user.is_authenticated() == False:
        try:
            user = User.objects.filter(id=request.session._session_cache['_auth_user_id'])[0]
            request.user = user
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

    return render(request,
                  'hlar/hlar_top.html',     # 使用するテンプレート
                  {
                    'user': request.user,
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

def client(access_token, access_token_secret):
    # api = twitter.Api(consumer_key=consumer_key,
    #                   consumer_secret=consumer_secret,
    #                   access_token_key=access_token,
    #                   access_token_secret=access_token_secret,
    #                   cache=None)
    #
    # tweets = api.GetSearch(term=u"#今日")
    # for tweet in tweets:
    #     print(tweet.text)


    CK = consumer_key                             # Consumer Key
    CS = consumer_secret         # Consumer Secret
    AT = access_token            # Access Token
    AS = access_token_secret     # Accesss Token Secert

    # タイムライン取得用のURL
    url = "https://api.twitter.com/1.1/statuses/home_timeline.json"

    # とくにパラメータは無い
    params = {}

    # OAuth で GET
    twitter = OAuth1Session(CK, CS, AT, AS)
    req = twitter.get(url, params = params)

    if req.status_code == 200:
        # レスポンスはJSON形式なので parse する
        timeline = json.loads(req.text)
        # 各ツイートの本文を表示
        for tweet in timeline:
            print(tweet["text"])

    else:
        # エラーの場合
        print ("Error: %d" % req.status_code)


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
            form = UserForm(data=request.POST)  # ← 受け取ったPOSTデータを渡す
            if form.is_valid():  # ← 受け取ったデータの正当性確認
                form.save()
                # form.user_edit()
                pass  # ← 正しいデータを受け取った場合の処理
            else:
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
    # if not request.user.is_authenticated():
    #         return HttpResponseRedirect('/login/?next=%s' % request.path)

#    return HttpResponse('ターゲットの一覧')
    # targets = Target.objects.all().order_by('id')

    # @ToDo user_idを動的に入れる
    targets = get_targets_user_id(1)


    return render(request,
                  'hlar/target_list.html',     # 使用するテンプレート
                  {'targets': targets})         # テンプレートに渡すデータ

def target_edit(request, target_id=None):
    # return HttpResponse('ターゲットの編集')

    if target_id:   # target_id が指定されている (修正時)
        target = get_object_or_404(Target, pk=target_id)
    else:         # target_id が指定されていない (追加時)
        target = Target()

    if request.method == 'POST':
        # POST 時

        ######## ターゲットファイル
        filePath = TARGET_FILE_PATH + request.POST['target_file_name']

        # file読み込み
        with open(filePath, 'rb') as f:
            contents = f.read()

        # base64でencode
        encTargetFileBase64 = base64.b64encode(contents)
        encTargetFile = encTargetFileBase64.decode('utf-8')


        ######## meta テキスト
        #### テキスト作成
        meta_file_name = request.POST['target_file_name'].replace('.','') + '.txt'
        metaPath = TARGET_FILE_PATH + meta_file_name

        # metaContent = "{\n" \
        #                 '\t"title": "DEATHRO -CRAZY FOR YOU- music video",\n' \
        #                 '\t"url" : "http://zine.hiliberate.biz/movie/deathro_crazy_for_you.mp4"\n' \
        #                '}'

        contentsFile = request.FILES['contents']

        metaContent = "{\n" \
                        '\t"title": "DEATHRO -CRAZY FOR YOU- music video",\n' \
                        '\t"url" : "https://test-hlar.s3.amazonaws.com/' + contentsFile.name + '"\n' \
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


        ######## ターゲット名
        target_name = request.POST['target_name']


        ######## Vuforia API で登録
        response_content = add_target(max_num_results='',
                                 include_target_data=encMetaFile,
                                 image=encTargetFile,
                                 target_name=target_name)

        print('4444')
        print(response_content)

        # if response_content['result_code'] == 'TargetNameExist'
        #
        # else :

        # if status == 200:
        #     print(query_response)
        #     # sys.exit(0)
        # else:
        #     print(status)
        #     print(query_response)
        #     # sys.exit(status)

        if judge_vws_result(response_content['result_code']):
            ######## S3に動画を保存

            #### まず一時的にサーバーに保存
            # 保存パス(ファイル名含む)
            filePath = TARGET_FILE_PATH + contentsFile.name

            print("filePath")
            print(filePath)

            # ファイルが存在していれば削除
            if default_storage.exists(filePath):
                default_storage.delete(filePath)

            # ファイルを保存
            path = default_storage.save(filePath, ContentFile(contentsFile.read()))

            bucket_name = 'test-hlar'
            key_name = contentsFile.name

            print("key_name")
            print(key_name)

            client = boto3.client('s3')
            client.upload_file(filePath, bucket_name, key_name)

            #s3にアップした動画を公開する
            # s3 = boto3.resource('s3')
            # bucket = s3.Bucket(bucket_name)
            # obj = bucket.Object(key_name)
            # obj.

            s3 = boto3.resource('s3')
            object_acl = s3.ObjectAcl(bucket_name, key_name)
            response = object_acl.put(ACL='public-read')

            ######## DBに登録
            target.content_name = key_name
            target.img_name = request.POST['target_file_name']
            target.user_id = 1 #@ToDo 決め打ち
            target.vuforia_target_id = response_content['target_id']

            # target = form.save(commit=False)

            target.save()

            ######## 一時ファイルを削除  @ToDo いずれ画像もs3にアップしてここで一時ファイルを削除する。
            default_storage.delete(filePath)    #contents

            return render(request, 'hlar/target_edit.html', dict(msg='登録が完了しました。'))
        else:
            return render(request, 'hlar/target_edit.html', dict(msg=response_content['result_code']))



        # form = TargetForm(request.POST, instance=target)  # POST された request データからフォームを作成
        # if form.is_valid():    # フォームのバリデーション
        #     target = form.save(commit=False)
        #     target.save()
        #     return redirect('hlar:target_list')
    else:
        # GET 時
        form = TargetForm(instance=target)  # target インスタンスからフォームを作成

#    c = Context({"my_name": "Adrian"})

    return render(request, 'hlar/target_edit.html', dict(form=form, target_id=target_id))

def target_del(request, target_id):
    return HttpResponse('ターゲットの削除')

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


def twitter_login(request):

    # Create your consumer with the proper key/secret.
    consumer = oauth.Consumer(key=consumer_key,
        secret=consumer_secret)

    # Request token URL for Twitter.
    request_token_url = "https://api.twitter.com/oauth/request_token"

    # Create our client.
    client = oauth.Client(consumer)

    # The OAuth Client request works just like httplib2 for the most part.
    resp, content = client.request(request_token_url, "GET")

    content_str = content.decode('utf-8')

    request_token = dict(parse_qsl(content_str))

    url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])

    #### request_token と request_token_secret を保存
    # DBに保存
    # oauth_obj = OauthTbl()
    # oauth_obj.oauth_token = request_token['oauth_token']
    # oauth_obj.oauth_token_secret = request_token['oauth_token_secret']
    # oauth_obj.save()

    # sessionに保存
    request.session['oauth_token'] = request_token['oauth_token']
    request.session['oauth_token_secret'] = request_token['oauth_token_secret']


    return HttpResponseRedirect(url)






    # print(content.split('&'))
    # request_token = dict(parse_qsl(content))

    # 認証ページに遷移
    # url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])
    # url = 'http://twitter.com/oauth/authenticate?oauth_token=2UsavwAAAAAA1SEBAAABXOcW3d0'
    # print('<meta http-equiv="refresh"content="1; url=%s">' % url)

    # return HttpResponseRedirect(url)

    # # consumer = oauth2.Consumer
    # # print(consumer)
    # consumer = oauth2.Consumer(key=consumer_key, secret=consumer_secret)
    # client = oauth2.Client(consumer)
    # # reqest_token を取得
    # resp, content = client.request(request_token_url, 'GET')
    #
    # print(content)
    #
    # request_token = dict(parse_qsl(content))
    #
    # # 認証ページに遷移
    # url = '%s?oauth_token=%s' % (authenticate_url, request_token['oauth_token'])
    # print('<meta http-equiv="refresh"content="1; url=%s">' % url)
    #
    # # request_token と request_token_secret を保存
    # con = sqlite3.connect('oauth.db')
    # con.execute(u'insert into oauth values (?, ?)', (request_token['oauth_token'], request_token['oauth_token_secret']))
    # con.commit()
    # con.close()

def parse_qsl(url):
    param = {}
    for i in url.split('&'):
        _p = i.split('=')
        param.update({_p[0]: _p[1]})
    return param





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



        # user = self.get_object()
        # serializer = PasswordSerializer(data=request.data)
        # if serializer.is_valid():
        #     user.set_password(serializer.data['password'])
        #     user.save()
        #     return Response({'status': 'password set'})
        # else:
        #     return Response(serializer.errors,
        #                     status=status.HTTP_400_BAD_REQUEST)
