DEBUG = True
# DEBUG = False
ALLOWED_HOSTS = ["*"]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'universe',
        'USER': 'root',
        'PASSWORD':'masahi0205',
        'HOST': 'test-hlar.c1ebqmlevvpb.us-east-1.rds.amazonaws.com',
        'PORT': 3306,
    }
}

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '110344682483-fqpd4fkdb42gtc0pf172f61s3gh2lid2.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'pxJBS6A7F5qgiavEQNbr0qU8'

# STRIPE 決済設定
STRIPE_PUBLISHABLE_KEY = 'pk_test_kq2QUHQQbfbIiz6RdJEbj9DU'
STRIPE_API_KEY = 'sk_test_TwoBPzByKz7FZ35aoeBlbuTl'



# エラー「Site matching query does not exist. 」を解消する為
SITE_ID=4

# ターゲット フリーで登録できる数
TARGET_LIMIT_COUNT = 5

# ターゲット画像のMAXサイズ
TARGET_SIZE_LIMIT = 2000000

# コンテンツ動画のMAXサイズ
CONTENTS_SIZE_LIMIT = 40000000

# S3 バケット名
S3_BUCKET_NAME = 'hlar-test'

# URL ROOT
URL_ROOT = 'https://test-universe.hiliberate.biz/'
