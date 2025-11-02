from pathlib import Path
import os # Assure-toi que os est importé


SECRET_KEY = 'django-insecure-un-secret-ici-peu-importe-pour-le-moment'


INSTALLED_APPS = [
    # Applications de base de Django (LA PARTIE MANQUANTE)
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Tes applications
    'PhishEye.bases_donnees',
    'frontend',
]

BASE_DIR = Path(__file__).resolve().parent.parent


ROOT_URLCONF = 'PhishEye.urls'
DEBUG = True 
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'phisheye_db',
        'USER': 'sherko',
        'PASSWORD': 'sherko',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')], # <--- C'EST CETTE LIGNE QUI NOUS INTÉRESSE
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',      # ⚠️ requis
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',   # ⚠️ requis
    'django.contrib.messages.middleware.MessageMiddleware',      # ⚠️ requis
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

STATIC_URL = '/static/'



