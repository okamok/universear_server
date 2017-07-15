DEBUG = False
ALLOWED_HOSTS = ["*"]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'test_python',
        'USER': 'root',
        'PASSWORD':'masahi0205',
        'HOST': 'test-hlar.c1ebqmlevvpb.us-east-1.rds.amazonaws.com',
        'PORT': 3306,
    }
}

SOCIAL_AUTH_TWITTER_KEY = '05WxUGIG4paZZZWj22cZJR6qC'
SOCIAL_AUTH_TWITTER_SECRET = 'zodNRE2HNnaOQyQAzMyg9xPdA7UunVcVdXkElkTO4NaAwQYxya'

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '110344682483-j6lbc554or0gnq3rd17o3k48i3cpbti6.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'C9Qj9F_sy0J0LNwNrnTVha5V'
