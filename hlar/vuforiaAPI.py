import httplib
import hashlib
import mimetypes
import hmac
import base64
from email.utils import formatdate
import sys

# The hostname of the Cloud Recognition Web API
CLOUD_RECO_API_ENDPOINT = 'cloudreco.vuforia.com'

def compute_md5_hex(data):
    """Return the hex MD5 of the data"""
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()


def compute_hmac_base64(key, data):
    """Return the Base64 encoded HMAC-SHA1 using the provide key"""
    h = hmac.new(key, None, hashlib.sha1)
    h.update(data)
    return base64.b64encode(h.digest())


def authorization_header_for_request(access_key, secret_key, method, content, content_type, date, request_path):
    """Return the value of the Authorization header for the request parameters"""
    components_to_sign = list()
    components_to_sign.append(method)
    components_to_sign.append(str(compute_md5_hex(content)))
    components_to_sign.append(str(content_type))
    components_to_sign.append(str(date))
    components_to_sign.append(str(request_path))
    string_to_sign = "\n".join(components_to_sign)
    signature = compute_hmac_base64(secret_key, string_to_sign)
    auth_header = "VWS %s:%s" % (access_key, signature)
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
        lines.append(value)
    lines.append('--' + BOUNDARY + '--')
    lines.append('')
    body = CRLF.join(lines)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def send_query(access_key, secret_key, max_num_results, include_target_data, image):
    http_method = 'POST'
    date = formatdate(None, localtime=False, usegmt=True)

    path = "/v1/query"

    # The body of the request is JSON and contains one attribute, the instance ID of the VuMark
    with open(image, 'rb') as f:
        imagedata = f.read()

    content_type, request_body = encode_multipart_formdata([('include_target_data', include_target_data),
                                                            ('max_num_results', max_num_results)],
                                                           [('image', image, imagedata)])
    content_type_bare = 'multipart/form-data'

    # Sign the request and get the Authorization header
    auth_header = authorization_header_for_request(access_key, secret_key, http_method, request_body, content_type_bare,
                                                   date, path)
    print('aaaaaaa')
    print(auth_header)

    request_headers = {
        'Accept': 'application/json',
        'Authorization': auth_header,
        'Content-Type': content_type,
        'Date': date
    }

    # Make the request over HTTPS on port 443
    http = httplib.HTTPSConnection(CLOUD_RECO_API_ENDPOINT, 443)
    http.request(http_method, path, request_body, request_headers)

    response = http.getresponse()
    response_body = response.read()
    return response.status, response_body
