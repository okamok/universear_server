# import httplib

# import http.client
# import hashlib
# import mimetypes
# import hmac
# import base64
# import sys
# import json
# import requests
# from email.utils import formatdate
# from datetime import datetime
# from urllib.parse import urlparse, urlencode, quote_plus
# from time import mktime
# from hashlib import sha1, md5
# from hmac import new as hmac

import logging
import urllib.request, base64
import pytz
import json
import requests
import binascii
import hlar.views

from wsgiref.handlers import format_date_time
from datetime import datetime, timedelta, tzinfo
from time import mktime
from urllib.parse import urlparse, urlencode, quote_plus
from hashlib import sha1, md5
from hmac import new as hmac
from pprint import pprint
from hlar.models import User, Target



# The hostname of the Cloud Recognition Web API
CLOUD_RECO_API_ENDPOINT = 'cloudreco.vuforia.com'
HOST = 'https://vws.vuforia.com'
SERVER_ACCESS_KEYS = '6968bbd6779ed68181552a8449c786bf85bfe650'
SERVER_SECRET_KEYS = '5a244dbd3afd62b6808b65a55b3a9a63187e543b'
VWS_ERROR_MSG = ['RequestTimeTooSkewed', 'TargetNameExist', 'RequestQuotaReached', 'UnknownTarget',
    'BadImage', 'ImageTooLarge', 'MetadataTooLarge','DateRangeError', 'Fail']


class VuforiaBaseError(Exception):
    def __init__(self, exc, response):
        self.transaction_id = response['transaction_id']
        self.result_code = response['result_code']
        self.exc = exc

class VuforiaRequestQuotaReached(VuforiaBaseError):
    pass

class VuforiaAuthenticationFailure(VuforiaBaseError):
    pass

class VuforiaRequestTimeTooSkewed(VuforiaBaseError):
    pass

class VuforiaTargetNameExist(VuforiaBaseError):
    pass

class VuforiaUnknownTarget(VuforiaBaseError):
    pass

class VuforiaBadImage(VuforiaBaseError):
    pass

class VuforiaImageTooLarge(VuforiaBaseError):
    pass

class VuforiaMetadataTooLarge(VuforiaBaseError):
    pass

class VuforiaDateRangeError(VuforiaBaseError):
    pass

class VuforiaFail(VuforiaBaseError):
    pass


def compute_md5_hex(data):
    """Return the hex MD5 of the data"""
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()


def compute_hmac_base64(key, data):
    """Return the Base64 encoded HMAC-SHA1 using the provide key"""
    # h = hmac.new(key, None, hashlib.sha1)
    h = hmac.new(key.encode(), None, hashlib.sha1)
    h.update(data)
    return base64.b64encode(h.digest())


def authorization_header_for_request(method, content, content_type, date, request_path):
    """Return the value of the Authorization header for the request parameters"""
    components_to_sign = list()
    components_to_sign.append(method)
    # components_to_sign.append(str(compute_md5_hex(content)))
    components_to_sign.append(str(compute_md5_hex(content.encode('utf-8'))))
    components_to_sign.append(str(content_type))
    components_to_sign.append(str(date))
    components_to_sign.append(str(request_path))
    string_to_sign = "\n".join(components_to_sign)
    # signature = compute_hmac_base64(SERVER_SECRET_KEYS, string_to_sign)
    signature = compute_hmac_base64(SERVER_SECRET_KEYS, string_to_sign.encode('utf-8'))
    auth_header = "VWS %s:%s" % (SERVER_ACCESS_KEYS, signature)
    return auth_header


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """

    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    lines = []
    for (key, value) in fields:
        lines.append('--' + BOUNDARY)
        lines.append('Content-Disposition: form-data; name="%s"' % key)
        lines.append('')
        lines.append(value)
    for (key, filename, value) in files:
        lines.append('--' + BOUNDARY)
        lines.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        lines.append('Content-Type: %s' % get_content_type(filename))
        lines.append('')
        # lines.append(value)
        lines.append('aaaa')
    lines.append('--' + BOUNDARY + '--')
    lines.append('')

    # print(lines)
    body = CRLF.join(lines)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def add_target(max_num_results, include_target_data, image, target_name):

    data = {"name": target_name, "width": 320, "image": image,"application_metadata": include_target_data, "active_flag": 1}
    url = '%s/targets' % HOST
    data = json.dumps(data)

    headers = {'Content-Type': 'application/json; charset=utf-8'}
    req = requests.Request(method='POST', url=url, data=data,
                           headers=headers)
    response = _get_authenticated_response(req)

    # print('33333')
    # print (response)

    return json.loads(response.content.decode())

# hlar_target.user_id を指定してターゲットを取得
def get_targets_user_id(user_id):
    print('user_id =' + str(user_id))

    #### pythonのDBからデータ取得
    # targets_object = Target.objects.all()
    targets_object = Target.objects.filter(user_id=str(user_id))


    print('targets_object')
    # print(targets_object)
    pprint(vars(targets_object))


    targets = []
    for target in targets_object:
        #### Vuforia のデータを取得
        v_target = get_target_by_id(target.vuforia_target_id)

        #### 取得したデータに独自のデータをマージ
        v_target['id'] = target.id
        v_target['view_count'] = target.view_count
        v_target['view_count_limit'] = target.view_count_limit
        v_target['view_state'] = target.view_state
        v_target['content_name'] = target.content_name
        v_target['img_name'] = target.img_name

        targets.append(v_target)

    print('targets')
    # pprint(vars(targets))
    print(targets)

    return targets

def get_targets():
    targets = []
    for target_id in get_target_ids():
        targets.append(get_target_by_id(target_id))
    return targets

def get_target_by_id(target_id):
    url = '%s/targets/%s' % (HOST, target_id)
    req = requests.Request(method='GET', url=url)
    response = _get_authenticated_response(req)
    print(response)
    return json.loads(response.content.decode())['target_record']

def get_target_ids():
    url = '%s/targets' % HOST
    req = requests.Request(method='GET', url=url)
    response = _get_authenticated_response(req)
    return json.loads(response.content.decode())['results']

def get_target_id_from_name(name):
    targets = get_targets()

    for target in targets:
        if target.name == name:
            return target.target_id

    return False

def _get_authenticated_response(req):
    rfc1123_date = _get_rfc1123_date()

    print('rfc1123_date')
    print(rfc1123_date)

    string_to_sign =\
        req.method + "\n" +\
        _get_content_md5(req) + "\n" +\
        _get_content_type(req) + "\n" +\
        rfc1123_date + "\n" +\
        _get_request_path(req)

    print('string_to_sign')
    print(string_to_sign)

    signature = _hmac_sha1_base64(SERVER_SECRET_KEYS, string_to_sign)

    print('signature')
    print(signature)

    #print(type(signature))
    #print("signature: ", signature)

    req.headers['Date'] =  rfc1123_date
    auth_header = 'VWS %s:%s' % (SERVER_ACCESS_KEYS, signature)
    req.headers['Authorization'] = auth_header

    print('auth_header')
    print(auth_header)

    try:

        if not req.data:
            data_to_send = None
        else:
            data_to_send = req.data.encode()

        return _send(req.url, req.method, data=data_to_send,
                          headers=req.headers)

    except requests.exceptions.HTTPError as e:
        print("ERROR: ", e)
        response = json.loads(e.read().decode('utf-8'))

        result_code = response['result_code']
        if result_code == 'RequestTimeTooSkewed':
            raise VuforiaRequestTimeTooSkewed(e, response)
        elif result_code == 'TargetNameExist':
            raise VuforiaTargetNameExist(e, response)
        elif result_code == 'RequestQuotaReached':
            raise VuforiaRequestQuotaReached(e, response)
        elif result_code == 'UnknownTarget':
            raise VuforiaUnknownTarget(e, response)
        elif result_code == 'BadImage':
            raise VuforiaBadImage(e, response)
        elif result_code == 'ImageTooLarge':
            raise VuforiaImageTooLarge(e, response)
        elif result_code == 'MetadataTooLarge':
            raise VuforiaMetadataTooLarge(e, response)
        elif result_code == 'DateRangeError':
            raise VuforiaDateRangeError(e, response)
        elif result_code == 'Fail':
            raise VuforiaFail(e, response)
        else:
            logging.error("Couldn't process %s response from Vuforia" % response)

        raise e  # re-raise the initial exception if can't handle it


def _get_rfc1123_date():
    # サーバーのタイムゾーンがUTCになっていないとhttpアクセス時にエラーになる

    now = datetime.now()
    stamp = mktime(now.timetuple())
    return format_date_time(stamp)

def _get_content_md5(req):
    if req.data:
        return md5(req.data.encode()).hexdigest()
    return "d41d8cd98f00b204e9800998ecf8427e"

def _get_content_type(req):
    if req.method in ["POST", "PUT"]:
        return "application/json"
    return ""

def _get_request_path(req):
    o = urlparse(req.url)
    return o.path

def _hmac_sha1_base64(key, message):
    # On python3, HMAC needs bytes for key and msg.
    return base64.b64encode(
                hmac(key.encode(),
                     message.encode(),
                     sha1).digest()).decode()

def _send(url, method, data=None, headers=None, type=None):
    """
    method handler of requests
    """
    try:
        if method == 'POST':
            return requests.post(url=url, headers=headers, data=data)
        elif method == 'GET':
            return requests.get(url=url, headers=headers, data=data)
        elif method == 'PUT':
            return requests.put(url=url, headers=headers, data=data)
        elif method == 'DELETE':
            return requests.delete(url=url, headers=headers, data=data)
    except requests.exceptions.ConnectionError:
        return None

def judge_vws_result(result_code):
    """
    :param str result_code
    :return: result bool / true=エラーなし、false=エラー
    """

    if result_code in VWS_ERROR_MSG:
        ret = False
    else:
        ret = True

    return ret
