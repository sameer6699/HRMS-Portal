from celery import shared_task
from .views import fetch_support_emails_via_nylas

@shared_task
def fetch_emails_task():
    print("===== Celery Task Started =====")
    fetch_support_emails_via_nylas()
    print("===== Celery Task Completed =====")