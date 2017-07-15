DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'test_python',
        'USER': 'root',
        'PASSWORD':'password',
        'HOST': 'db',
        'PORT': 3306,
    }
}

SOCIAL_AUTH_TWITTER_KEY = '05WxUGIG4paZZZWj22cZJR6qC'
SOCIAL_AUTH_TWITTER_SECRET = 'zodNRE2HNnaOQyQAzMyg9xPdA7UunVcVdXkElkTO4NaAwQYxya'

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '110344682483-fqpd4fkdb42gtc0pf172f61s3gh2lid2.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'pxJBS6A7F5qgiavEQNbr0qU8'
