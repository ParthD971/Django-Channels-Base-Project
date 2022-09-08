# core/celery.py

import os
from celery import Celery
import dotenv

dotenv.load_dotenv()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
app = Celery("core")
app.conf.enable_utc = False
app.conf.update(timezone='Asia/Kolkata')

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
