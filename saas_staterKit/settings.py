import os
from pathlib import Path
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
    'unfold',  # before django.contrib.admin
    'unfold.contrib.filters',  # optional, if special filters are needed
    'unfold.contrib.forms',  # optional, if special form elements are needed
    'unfold.contrib.inlines',  # optional, if special inlines are needed
    'unfold.contrib.import_export',  # optional, if django-import-export package is used
    'unfold.contrib.guardian',  # optional, if django-guardian package is used
    'unfold.contrib.simple_history',  # optional, if django-simple-history package is used
    'django_tenants',  # Multi-tenancy support
    'django.contrib.admin',  # required
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
    'anymail',
    'organizations',
    'waitlist'
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
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'build/static')
# ]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# Media files (Uploaded files)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # Limit request size to 10 MB
CORS_ORIGIN_ALLOW_ALL = False

# Securely load allowed origins from environment variables
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")

# Ensure local development works in DEBUG mode
if DEBUG:
    CORS_ALLOWED_ORIGINS.extend([
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ])

# Allow credentials (cookies, tokens)
CORS_ALLOW_CREDENTIALS = True

# Define allowed methods and headers
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = [
    "x-requested-with",
    "content-type",
    "accept",
    "origin",
    "authorization",
    "accept-encoding",
    "access-control-allow-origin",
    "content-disposition",
    "x-github-delivery",
    "x-github-event",
    "x-github-hook-id",
    "x-github-hook-installation-target-id",
    "x-github-hook-installation-target-type",
    "x-hub-signature",
    "x-hub-signature-256",
]

# CORS_ALLOW_HEADERS = ["*"]
# Set CSRF trusted origins securely
CSRF_TRUSTED_ORIGINS = ["https://" + host for host in CORS_ALLOWED_ORIGINS if host]

# Ensure HTTPS is used
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Enable HTTP Strict Transport Security (HSTS)
SECURE_HSTS_SECONDS = 31536000  # One year
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# Prevent content sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# Enable XSS protection
SECURE_BROWSER_XSS_FILTER = True

# Prevent clickjacking
X_FRAME_OPTIONS = 'DENY'

# Prevent exposing the Host header
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Enforce a strong Content Security Policy (CSP)
# CSP_DEFAULT_SRC = ("'self'",)
# CSP_SCRIPT_SRC = ("'self'", "https://trusted.cdn.com")
# CSP_STYLE_SRC = ("'self'", "https://trusted.cdn.com")
# CSP_IMG_SRC = ("'self'", "data:", "https://trusted.cdn.com")



AUTH_USER_MODEL = "accounts.UserAccount"

# Default email backend for local development
if DEBUG:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = "smtp.gmail.com"
    EMAIL_PORT = 587
    EMAIL_HOST_USER = os.getenv("EMAIL_APP_USER_HOST")
    EMAIL_HOST_PASSWORD = os.getenv("EMAIL_APP_HOST_PASSWORD")
    EMAIL_USE_TLS = True

# Production email backend using Brevo
else:
    EMAIL_BACKEND = "anymail.backends.brevo.EmailBackend"
    ANYMAIL = {
        "BREVO_API_KEY": os.getenv("BREVO_API_KEY"),
        "BREVO_API_URL": "https://api.brevo.com/v3",  # Optional, in case the default changes
    }

REST_FRAMEWORK = {
    "COERCE_DECIMAL_TO_STRING": False,

    # Throttling (Rate Limiting)
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "500/day",  # Rate limit for authenticated users (by user ID)
        "anon": "10/minute",  # Rate limit for unauthenticated users (by IP)
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

SESAME_MAX_AGE = 600  # Shorten link expiry to 10 minutes
SESAME_ONE_TIME = True  # Ensure links are single-use
SESAME_TOKEN_NAME = "token"  # Use a more descriptive token name
SESAME_TOKEN_LENGTH = 80  # Increase token length for stronger security
SESAME_SIGNING_ALGORITHM = "HS512"  # Stronger signing algorithm
SESAME_DOMAIN = os.getenv("HOST_DOMAIN", "yourdomain.com")  # Explicit fallback

# Secure Cookies
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = "Strict"  # No cross-site usage

# Additional Django Settings
CSRF_COOKIE_HTTPONLY = True  # Prevent JavaScript access
CSRF_COOKIE_SAMESITE = "Strict"  # Prevent CSRF via cross-origin requests




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


UNFOLD = {
    "SITE_TITLE": "Push to Post Admin",
    "SITE_HEADER": "Push to Post",
    "SITE_SUBHEADER": "Effortless Content Automation",
    "SITE_URL": "/",
    "SITE_SYMBOL": "send",  # Updated icon symbol to match the app's "push" theme
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": True,  # Assuming we might not need this for the admin panel
    "SHOW_BACK_BUTTON": True,
    # "THEME": "dark",  # Force dark theme for consistency
    "BORDER_RADIUS": "8px",  # Subtle rounded corners for a modern look

    "COLORS": {
        "base": {
            "50": "245 245 245",  # Very light grey for backgrounds
            "100": "235 235 235",
            "200": "220 220 220",
            "300": "200 200 200",
            "400": "160 160 160",
            "500": "120 120 120",  # Neutral grey for general elements
            "600": "80 80 80",
            "700": "60 60 60",
            "800": "40 40 40",  # Darker greys for components
            "900": "20 20 20",  # Near-black for high-contrast elements
            "950": "10 10 10",  # Almost pitch black for the darkest elements
        },
        "primary": {
            "50": "250 250 250",  # Very light grey for subtle highlights
            "100": "240 240 240",
            "200": "225 225 225",
            "300": "200 200 200",
            "400": "150 150 150",
            "500": "100 100 100",
            "600": "80 80 80",
            "700": "60 60 60",
            "800": "40 40 40",
            "900": "30 30 30",
            "950": "20 20 20",
        },
        "font": {
            "subtle-light": "var(--color-base-500)",  # Mid-grey for less important text
            "subtle-dark": "var(--color-base-400)",
            "default-light": "var(--color-base-800)",  # Darker grey for default text
            "default-dark": "var(--color-base-200)",
            "important-light": "var(--color-base-900)",  # Strong contrast for important text
            "important-dark": "var(--color-base-50)",
        },
    },

    "EXTENSIONS": {
        "modeltranslation": {
            "flags": {
                "en": "🇬🇧",
                "fr": "🇫🇷",
                "nl": "🇧🇪",
            },
        },
    },

    "SIDEBAR": {
        "show_search": True,  # Enable search to quickly navigate admin sections
        "show_all_applications": False,  # Show all apps in a dropdown for easier management
        "separator": True,  # Top border
        "collapsible": True,  # Collapsible group of links
    },
}



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

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'formatters': {
#         'verbose': {
#             'format': '[{asctime}] {levelname} {name} - {message}',
#             'style': '{',
#         },
#     },
#     'handlers': {
#         'console': {
#             'class': 'logging.StreamHandler',
#             'formatter': 'verbose',
#         },
#     },
#     'root': {
#         'handlers': ['console'],
#         'level': 'DEBUG',  # Or INFO in production
#     },
# }



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
