"""
Django settings for saas_staterKit project.

Generated by 'django-admin startproject' using Django 5.1.2.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

import os
from pathlib import Path
from celery.schedules import crontab
from datetime import timedelta
from dotenv import load_dotenv
import dj_database_url

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
# Get the custom admin URL from the environment variable, with a default fallback
CUSTOM_ADMIN_URL = os.getenv('CUSTOM_ADMIN_URL', 'my_custom_admin_url')  # Fallback to 'my_custom_admin_url' if not set
FRONTEND_DOMAIN = os.getenv("FRONTEND_DOMAIN", "http://localhost:3000")
SITE_NAME = os.getenv("SITE_NAME", "Your Site")
# Fetch the Fernet key from environment variables
FERNET_KEY = os.getenv('DJANGO_FERNET_KEY')
DOMAIN = os.getenv("DOMAIN", "localhost:3000")

AI_API_KEY = os.getenv("NVIDIA_API_KEY", "")
AI_BASE_URL = os.getenv("NVIDIA_AI_BASE_URL", "")
TWITTER_API_KEY = os.getenv("TWITTER_API_KEY", "")
TWITTER_API_SECRET = os.getenv("TWITTER_API_SECRET", "")
TWITTER_ACCESS_KEY = os.getenv("TWITTER_ACCESS_KEY", "")
TWITTER_ACCESS_SECRET_KEY = os.getenv("TWITTER_ACCESS_SECRET_KEY", "")
TWITTER_BEARER_TOKEN = os.getenv("TWITTER_BEARER_TOKEN", "")
TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID", "")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET", "")
TWITTER_AUTH_URL = os.getenv("TWITTER_AUTH_URL", "")
TWITTER_TOKEN_URL = os.getenv("TWITTER_TOKEN_URL", "")
TWITTER_REDIRECT_URI = os.getenv("TWITTER_REDIRECT_URI", "")

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "")
LINKEDIN_SCOPE = "openid profile w_member_social email"


TWITTER_SCOPES = [
    "tweet.read",
    "users.read",
    "tweet.write"
]


DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "no-reply@yoursite.com")
# Fetch the email from the environment or default to a specific one if not set
DJANGO_PRODUCT_OWNER_EMAIL = os.getenv('DJANGO_PRODUCT_OWNER_EMAIL', 'brilliantmakanju7+owner@example.com')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG")

ALLOWED_HOSTS = ['localhost', '127.0.0.1', "*", "djangosaasstarterkit-production.up.railway.app"]

# Application definitions
# **SHARED_APPS** is for apps that will be shared across all tenants.
SHARED_APPS = [
    'django_tenants',  # Multi-tenancy support

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'djoser',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'django_extensions',
    'oauth2_provider',
    'social_django',
    'drf_social_oauth2',
    'background_task',
    'sesame',
    'django_celery_beat',

    'accounts',
    'organizations',
]


# **TENANT_APPS** is for apps that will be specific to each tenant.
TENANT_APPS = [
    'core',
    'notifications'
]

INSTALLED_APPS = SHARED_APPS + [
    app for app in TENANT_APPS if app not in SHARED_APPS
]


# Using the TenantSyncRouter to route tenant queries to the correct schema
DATABASE_ROUTERS = ['django_tenants.routers.TenantSyncRouter']


MIDDLEWARE = [
    'accounts.middleware.SubdomainMiddleware',
    'accounts.middleware.CustomJWTAuthenticationMiddleware',
    'django_tenants.middleware.TenantMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware'
]

# Tenant and domain model configuration
TENANT_MODEL = "organizations.Organization"  # This is your custom organization model
TENANT_DOMAIN_MODEL = "organizations.Domain"  # Domain model for each tenant
# Public schema for user-related functionality
PUBLIC_SCHEMA_NAME = 'public'  # The public schema for user management (shared for all tenants)
SHOW_PUBLIC_IF_NO_TENANT_FOUND = True

ROOT_URLCONF = 'saas_staterKit.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect'
            ],
        },
    },
]

WSGI_APPLICATION = 'saas_staterKit.wsgi.application'

CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Redis URL for the broker
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_TIMEZONE = 'UTC'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases
# Use this configuration for connecting to an SQLite database (simple setup for local development/testing).
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',  # SQLite database file located in the BASE_DIR
#     }
# }

# Use this configuration to connect to a PostgreSQL database.
# Requires environment variables for security and flexibility in production.
# DATABASES = {
#     'default': {
#         'ENGINE': 'django_tenants.postgresql_backend',
#         'NAME': os.getenv('DB_NAME'),          # PostgreSQL database name
#         'USER': os.getenv('DB_USERNAME'),       # PostgreSQL username
#         'PASSWORD': os.getenv('DB_PASSWORD'),   # PostgreSQL user password
#         'HOST': 'localhost',              # Database server host (localhost for local dev)
#         'PORT': '5432',                   # Default PostgreSQL port
#     }
# }


DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv("DATABASE_URL"),
        engine="django_tenants.postgresql_backend"
    )
}

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'console': {
#             'level': 'DEBUG',
#             'class': 'logging.StreamHandler',
#         },
#         'file': {
#             'level': 'ERROR',
#             'class': 'logging.FileHandler',
#             'filename': 'django_error.log',
#         },
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['console', 'file'],
#             'level': 'DEBUG',
#             'propagate': True,
#         },
#     },
# }

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

TOKEN_MODEL = None


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


CELERY_BEAT_SCHEDULE = {
    'publish_pending_posts': {
        'task': 'core.tasks.publish_pending_post',
        'schedule': crontab(minute='*/1'),  # Every minute
    },
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
STATICSTORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'build/static')
]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = ['http://localhost:3000']

CORS_ALLOW_HEADERS = (
    "x-requested-with",
    "content-type",
    "accept",
    "origin",
    "authorization",
    "accept-encoding",
    "access-control-allow-origin",
    "content-disposition",
)

CSRF_TRUSTED_ORIGINS = ["https://" + host for host in ALLOWED_HOSTS]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

AUTH_USER_MODEL = "accounts.UserAccount"

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = os.getenv('EMAIL_APP_USER_HOST')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_APP_HOST_PASSWORD')
EMAIL_USE_TLS = True

REST_FRAMEWORK = {
    "COERCE_DECIMAL_TO_STRING": False,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],

    "DEFAULT_FILTER_BACKENDS": (
        # "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.OrderingFilter",
        "rest_framework.filters.SearchFilter",
    ),
    "DEFAULT_THROTTLING_CLASSES": (
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        'user': '50/minute',
        'anon':  '50/minute'
    },
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 30,
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',  # django-oauth-toolkit >= 1.0.0
        'rest_framework_social_oauth2.authentication.SocialAuthentication',
    ),
}

CSRF_COOKIE_SECURE = True

### Testing SIMPLE_JWT config

# SIMPLE_JWT = {
#     # Specifies the prefix for the authentication header; "JWT" means you must send tokens like "JWT <token>".
#     'AUTH_HEADER_TYPES': ('Bearer',),
#
#     # Defines how long the access token is valid before it expires. Here, it is set to 5 minutes.
#     'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
#
#     # Defines how long the refresh token is valid before it expires. Here, it is set to 5 day.
#     'REFRESH_TOKEN_LIFETIME': timedelta(days=5),
#
#     # Specifies the classes that will be used to create the tokens. We are using the default AccessToken class.
#     'AUTH_TOKEN_CLASSES': (
#         'rest_framework_simplejwt.tokens.AccessToken',
#     ),
#
#     # If set to True, refresh tokens will be blacklisted after use. This means once you use a refresh token to get a new access token, it cannot be reused.
#     'BLACKLIST_AFTER_ROTATION': True,  # Enable blacklisting of refresh tokens after they are rotated
#     'ROTATE_REFRESH_TOKENS': True,
#
#     # Settings for token blacklisting
#     'TOKEN_BLACKLIST': {
#         'TOKEN_TYPE': 'refresh',
#         'USER_ID_FIELD': 'id',  # The field that represents the user ID in your User model
#         'USER_ID_CLAIM': 'user_id',  # The claim to be used to find the user ID
#     },
#
#     'UPDATE_LAST_LOGIN': True,
#
#     'ALGORITHM': 'HS256',
#
#     'VERIFYING_KEY': None,
#     'AUDIENCE': None,
#     'ISSUER': None,
#     'JWK_URL': None,
#     'LEEWAY': 0,
#
#     'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
#     'USER_ID_FIELD': 'id',
#     'USER_ID_CLAIM': 'user_id',
#     'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
#
#     'TOKEN_TYPE_CLAIM': 'token_type',
#     'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
#
#     'JTI_CLAIM': 'jti',
#
#     'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
#     'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
#     'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=5),
# }

### Testing SIMPLE_JWT config

# SIMPLE_JWT = {
#     # Specifies the prefix for the authentication header; "JWT" means you must send tokens like "JWT <token>".
#     'AUTH_HEADER_TYPES': ('Bearer',),
#
#     # Defines how long the access token is valid before it expires. Here, it is set to 5 minutes.
#     'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
#
#     # Defines how long the refresh token is valid before it expires. Here, it is set to 5 day.
#     'REFRESH_TOKEN_LIFETIME': timedelta(days=5),
#
#     # Specifies the classes that will be used to create the tokens. We are using the default AccessToken class.
#     'AUTH_TOKEN_CLASSES': (
#         'rest_framework_simplejwt.tokens.AccessToken',
#     ),
#
#     # If set to True, refresh tokens will be blacklisted after use. This means once you use a refresh token to get a new access token, it cannot be reused.
#     'BLACKLIST_AFTER_ROTATION': True,  # Enable blacklisting of refresh tokens after they are rotated
#     'ROTATE_REFRESH_TOKENS': True,
#
#     # Settings for token blacklisting
#     'TOKEN_BLACKLIST': {
#         'TOKEN_TYPE': 'refresh',
#         'USER_ID_FIELD': 'id',  # The field that represents the user ID in your User model
#         'USER_ID_CLAIM': 'user_id',  # The claim to be used to find the user ID
#     },
#
#     'UPDATE_LAST_LOGIN': True,
#
#     'ALGORITHM': 'HS256',
#
#     'VERIFYING_KEY': None,
#     'AUDIENCE': None,
#     'ISSUER': None,
#     'JWK_URL': None,
#     'LEEWAY': 0,
#
#     'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
#     'USER_ID_FIELD': 'id',
#     'USER_ID_CLAIM': 'user_id',
#     'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
#
#     'TOKEN_TYPE_CLAIM': 'token_type',
#     'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
#
#     'JTI_CLAIM': 'jti',
#
#     'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
#     'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
#     'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=5),
# }

SIMPLE_JWT = {
    # Authentication Header Prefix
    "AUTH_HEADER_TYPES": ("Bearer",),
    # Authentication Header Prefix
    "AUTH_HEADER_TYPES": ("Bearer",),

    # Token Expiration Times
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),  # Short-lived access tokens
    "REFRESH_TOKEN_LIFETIME": timedelta(days=5),  # Longer-lived refresh tokens

    # Rotation and Blacklisting
    "ROTATE_REFRESH_TOKENS": True,  # Rotate refresh tokens upon use
    "BLACKLIST_AFTER_ROTATION": True,  # Blacklist old refresh tokens

    # Security Features
    "ALGORITHM": "HS256",  # Default algorithm for JWT
    "SIGNING_KEY": SECRET_KEY,  # Use Django's secret key
    "VERIFYING_KEY": None,  # Optional public key for asymmetric signing
    "AUDIENCE": None,  # Define audience for the token
    # "ISSUER": "yourdomain.com",  # Define token issuer

    # Token Claims
    "USER_ID_FIELD": "id",  # Map to the user ID field
    "USER_ID_CLAIM": "user_id",  # Claim to store the user ID
    "TOKEN_TYPE_CLAIM": "token_type",  # Define the type of token
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    # Sliding Token Settings
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=5),
}
# Sesame Configuration
SESAME_MAX_AGE = 9000  # Links expire in 15 minutes (900 seconds)
SESAME_ONE_TIME = True  # Magic link can be used only once
SESAME_TOKEN_NAME = "token"  # Explicit token name in the query string
SESAME_TOKEN_LENGTH = 70  # Increase token length for stronger security
SESAME_SIGNING_ALGORITHM = "HS512"  # Use a stronger hashing algorithm (default is HS256)
# SESAME_DOMAIN = "yourdomain.com"  # Restrict tokens to your domain only

# Secure Cookies for Magic Link
# SESSION_COOKIE_SECURE = True  # Use HTTPS for cookies
# SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to cookies
# SESSION_COOKIE_SAMESITE = "Strict"  # Prevent cross-site cookie usage


DJOSER = {
    'TOKEN_MODEL': None,
    'LOGIN_FIELD': 'email',
    'USER_CREATE_PASSWORD_RETYPE': True,
    'JWT_SERIALIZER': 'accounts.serializers.CustomTokenObtainPairSerializer',
    'USERNAME_CHANGED_EMAIL_CONFIRMATION': True,
    'PASSWORD_CHANGED_EMAIL_CONFIRMATION': True,
    'SEND_CONFIRMATION_EMAIL': True,
    'SET_USERNAME_RETYPE': True,
    'SET_PASSWORD_RETYPE': True,
    'PASSWORD_RESET_CONFIRM_URL': 'auth/reset/{uid}/{token}',
    'USERNAME_RESET_CONFIRM_URL': 'reset/confirm/{uid}/{token}',
    'ACTIVATION_URL': 'inbox/{uid}/{token}',
    'SEND_ACTIVATION_EMAIL': True,
    'SOCIAL_AUTH_TOKEN_STRATEGY': 'djoser.social.token.jwt.TokenStrategy',
    'SOCIAL_AUTH_ALLOWED_REDIRECT_URIS': ['http://localhost:8000/google'],
    'SERIALIZERS': {
        'user_create': 'accounts.serializers.UserCreateSerializer',
        'user': 'accounts.serializers.UserCreateSerializer',
        'current_user': 'accounts.serializers.UserCreateSerializer',
        'user_delete': 'djoser.serializers.UserDeleteSerializer',
        'token_obtain_pair': 'accounts.serializers.CustomTokenObtainPairSerializer',
    },
}

AUTHENTICATION_BACKENDS = (
    # 'social_core.backends.github.GithubOAuth2',  # For GitHub (if you are using GitHub)
    # Google  OAuth2
    'social_core.backends.google.GoogleOAuth2',
    # drf-social-oauth2
    'drf_social_oauth2.backends.DjangoOAuth2',
    'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
    # Django
    'django.contrib.auth.backends.ModelBackend',  # Default authentication backend
    'sesame.backends.ModelBackend',
)





# Social Auth Google OAuth2 settings
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.getenv('GOOGLE_OAUTH2_API_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.getenv('GOOGLE_OAUTH2_API_SECRET')
# Define SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE to get extra permissions from Google.
SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]
SOCIAL_AUTH_GOOGLE_OAUTH2_EXTRA_DATA = ['first_name', 'last_name']

# Redirect URLs
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# Social Auth Settings
SOCIAL_AUTH_URL_NAMESPACE = 'social'
