import logging
# import urllib.request, base64
# import pytz
import json
import requests
# import binascii
import hlar.views

from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta, tzinfo
from time import mktime
from urllib.parse import urlparse, urlencode, quote_plus
from hashlib import sha1, md5
from hmac import new as hmac
from pprint import pprint
from hlar.models import User, Target, Oauth as OauthTbl
# import twitter


from requests_oauthlib import OAuth1Session


# def get_twitter_account(consumer_key, consumer_secret, access_token, access_token_secret):
#     """アクセストークンなどを使ってoauth認証されたアプリからメアドなどを取得してuserへinsert"""
#     #### mail,nameをtwitterからgetする
#
#     # アカウント情報 取得
#     url = "https://api.twitter.com/1.1/account/verify_credentials.json"
#
#     # とくにパラメータは無い
#     # params = {}
#     params = {"include_email": "true"}
#
#     # OAuth で GET
#     twitterClient = OAuth1Session(consumer_key, consumer_secret, access_token, access_token_secret)
#     req = twitterClient.get(url, params = params)
#
#     print(req)
#
#     if req.status_code == 200:
#         # レスポンスはJSON形式なので parse する
#         account = json.loads(req.text)
#         # print(account)
#         return account
#     else:
#         # エラーの場合
#         print ("Error: %d" % req.status_code)
#
#
#
#     # twitterで
#     # api = twitter.Api(consumer_key=consumer_key,
#     #                   consumer_secret=consumer_secret,
#     #                   access_token_key=access_token,
#     #                   access_token_secret=access_token_secret,
#     #                   cache=None)
#     #
#     # account = api.VerifyCredentials(include_entities = None , skip_status = None , include_email = True)
#     # print(account)
#
#     return None
