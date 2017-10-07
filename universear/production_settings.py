DEBUG = False
ALLOWED_HOSTS = ["*"]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'universe',
        'USER': 'root',
        'PASSWORD':'masahi0205',
        'HOST': 'universe.cdwueyrsxbwv.us-east-1.rds.amazonaws.com',
        'PORT': 3306,
    }
}

SOCIAL_AUTH_TWITTER_KEY = '05WxUGIG4paZZZWj22cZJR6qC'
SOCIAL_AUTH_TWITTER_SECRET = 'zodNRE2HNnaOQyQAzMyg9xPdA7UunVcVdXkElkTO4NaAwQYxya'

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '110344682483-j6lbc554or0gnq3rd17o3k48i3cpbti6.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'C9Qj9F_sy0J0LNwNrnTVha5V'

STRIPE_API_KEY = 'sk_test_Po5fLfcGq5FnakXbyvB7IIO9'
STRIPE_PUBLISHABLE_KEY = 'pk_test_Qf9hdfU6fy6sKc09jZ4hKH5T'

# エラー「Site matching query does not exist. 」を解消する為
SITE_ID=2

# ターゲット フリーで登録できる数
TARGET_LIMIT_COUNT = 5

# コンテンツ動画のMAXサイズ
CONTENTS_SIZE_LIMIT = 40000000

# S3 バケット名
S3_BUCKET_NAME = 'universe-ar'
