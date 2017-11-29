DEBUG = True
# DEBUG = False
ALLOWED_HOSTS = ["*"]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'universe',
        'USER': 'root',
        'PASSWORD':'password',
        'HOST': 'db',
        'PORT': 3306,
    }
}

# SOCIAL_AUTH_TWITTER_KEY = '05WxUGIG4paZZZWj22cZJR6qC'
# SOCIAL_AUTH_TWITTER_SECRET = 'zodNRE2HNnaOQyQAzMyg9xPdA7UunVcVdXkElkTO4NaAwQYxya'

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '110344682483-fqpd4fkdb42gtc0pf172f61s3gh2lid2.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'pxJBS6A7F5qgiavEQNbr0qU8'

# STRIPE 決済設定
# STRIPE_PUBLISHABLE_KEY = 'pk_test_Qf9hdfU6fy6sKc09jZ4hKH5T'
# STRIPE_API_KEY = 'sk_test_Po5fLfcGq5FnakXbyvB7IIO9'
STRIPE_PUBLISHABLE_KEY = 'pk_test_kq2QUHQQbfbIiz6RdJEbj9DU'
STRIPE_API_KEY = 'sk_test_TwoBPzByKz7FZ35aoeBlbuTl'

# エラー「Site matching query does not exist. 」を解消する為
SITE_ID=4

# ターゲット フリーで登録できる数
TARGET_LIMIT_COUNT = 10

# ターゲット画像のMAXサイズ
TARGET_SIZE_LIMIT = 2000000

# コンテンツ動画のMAXサイズ
CONTENTS_SIZE_LIMIT = 40000000

# S3 バケット名
S3_BUCKET_NAME = 'hlar-test'
