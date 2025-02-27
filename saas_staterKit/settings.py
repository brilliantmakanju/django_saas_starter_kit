import os
from pathlib import Path
from celery.schedules import crontab
from datetime import timedelta
from dotenv import load_dotenv

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
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:3000/settings?tab=general")
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
# Check if HOST_DOMAIN is set in environment variables
HOST_DOMAIN = os.getenv("HOST_DOMAIN")
# SECURITY WARNING: don't run with debug turned on in production!
# Set DEBUG to False if HOST_DOMAIN is present, otherwise True
DEBUG = not bool(HOST_DOMAIN)

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# Allow wildcard domains only in DEBUG mode for local testing
if DEBUG:
    ALLOWED_HOSTS.append("*")  # Allow all in local development

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

# # Redis Configuration
# REDIS_USER = os.getenv("REDISUSER", "default")
# REDIS_PASSWORD = os.getenv("REDISPASSWORD", "")
# REDIS_HOST = os.getenv("REDISHOST", "redis")
# REDIS_PORT = os.getenv("REDISPORT", "6379")
#
# # Prevent empty password from breaking Redis URL
# REDIS_AUTH = f":{REDIS_PASSWORD}@" if REDIS_PASSWORD else ""
# REDIS_URL = f"redis://{REDIS_AUTH}{REDIS_HOST}:{REDIS_PORT}"
#
# # Celery Configuration
# CELERY_BROKER_URL = "redis://localhost:6379/0" if DEBUG else REDIS_URL
# CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)  # Ensure proper default
# CELERY_BEAT_SCHEDULER = os.getenv("CELERY_BEAT_SCHEDULER", "django_celery_beat.schedulers.DatabaseScheduler")
#
# CELERY_ACCEPT_CONTENT = ['json']
# CELERY_TASK_SERIALIZER = 'json'
# CELERY_TIMEZONE = 'UTC'
# CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
#
# # Celery Beat Task Scheduling
# CELERY_BEAT_SCHEDULE = {
#     'publish_pending_posts': {
#         'task': 'core.tasks.publish_pending_post',
#         'schedule': crontab(minute='*/1'),  # Runs every minute
#     },
# }
#
# # Redis Caching (Only for Production)
# if not DEBUG:
#     CACHES = {
#         "default": {
#             "BACKEND": "django.core.cache.backends.redis.RedisCache",
#             "LOCATION": REDIS_URL,
#         }
#     }



# Database
# Use this configuration to connect to a PostgreSQL database.
# # Requires environment variables for security and flexibility in production.
DATABASES = {
    'default': {
        'ENGINE': 'django_tenants.postgresql_backend',
        'NAME': os.getenv('DB_NAME'),          # PostgreSQL database name
        'USER': os.getenv('DB_USERNAME'),       # PostgreSQL username
        'PASSWORD': os.getenv('DB_PASSWORD'),   # PostgreSQL user password
        'HOST': os.getenv('DB_HOST', 'localhost'),              # Database server host (localhost for local dev)
        'PORT': os.getenv('DB_PORT', '5432'),                   # Default PostgreSQL port
        'CONN_MAX_AGE': 60,
    }
}

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

# CORS CONFIGURATION
CORS_ORIGIN_ALLOW_ALL = False
# Parse CORS_ALLOWED_ORIGINS from environment variables
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")

# Ensure local frontend works in DEBUG mode
if DEBUG:
    CORS_ALLOWED_ORIGINS.append("http://localhost:3000")

# Allow all subdomains of the main domain for CSRF protection
CSRF_TRUSTED_ORIGINS = ["https://" + host for host in ALLOWED_HOSTS]

CORS_ALLOW_CREDENTIALS = True  # Allow credentials (cookies, tokens)

CORS_ALLOW_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
]

CORS_ALLOW_HEADERS = [
    "x-requested-with",
    "content-type",
    "accept",
    "origin",
    "authorization",
    "accept-encoding",
    "access-control-allow-origin",
    "content-disposition",
]

AUTH_USER_MODEL = "accounts.UserAccount"

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = os.getenv('EMAIL_APP_USER_HOST')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_APP_HOST_PASSWORD')
EMAIL_USE_TLS = True

REST_FRAMEWORK = {
    "COERCE_DECIMAL_TO_STRING": False,

    # Throttling (Rate Limiting)
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "50/minute",  # Rate limit for authenticated users (by user ID)
        "anon": "20/minute",  # Rate limit for unauthenticated users (by IP)
    },

    # Filtering and Searching
    "DEFAULT_FILTER_BACKENDS": (
        # "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.OrderingFilter",
        "rest_framework.filters.SearchFilter",
    ),

    # Pagination
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 30,

    # Permissions
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),

    # Authentication Methods
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",  # django-oauth-toolkit >= 1.0.0
        "rest_framework_social_oauth2.authentication.SocialAuthentication",
    ),
}


CSRF_COOKIE_SECURE = True

### Testing SIMPLE_JWT config

SIMPLE_JWT = {
    # Authentication Header Prefix
    "AUTH_HEADER_TYPES": ("Bearer",),

    # Token Expiration Times
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),  # Short-lived access tokens
    "REFRESH_TOKEN_LIFETIME": timedelta(days=2),  # Longer-lived refresh tokens

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
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=2),
}
# Sesame Configuration
SESAME_MAX_AGE = 9000  # Links expire in 15 minutes (900 seconds)
SESAME_ONE_TIME = True  # Magic link can be used only once
SESAME_TOKEN_NAME = "token"  # Explicit token name in the query string
SESAME_TOKEN_LENGTH = 70  # Increase token length for stronger security
SESAME_SIGNING_ALGORITHM = "HS512"  # Use a stronger hashing algorithm (default is HS256)
SESAME_DOMAIN = os.getenv("HOST_DOMAIN")  # Restrict tokens to your domain only

# Secure Cookies for Magic Link
SESSION_COOKIE_SECURE = True  # Use HTTPS for cookies
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to cookies
SESSION_COOKIE_SAMESITE = "Strict"  # Prevent cross-site cookie usage


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

import sentry_sdk

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN", ""),
    # Add data like request headers and IP for users,
    # see https://docs.sentry.io/platforms/python/data-management/data-collected/ for more info
    send_default_pii=True,
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for tracing.
    traces_sample_rate=1.0,
    _experiments={
        # Set continuous_profiling_auto_start to True
        # to automatically start the profiler on when
        # possible.
        "continuous_profiling_auto_start": True,
    },
)
