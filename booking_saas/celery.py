"""
Celery configuration for background tasks and scheduled jobs.
"""
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'booking_saas.settings')

app = Celery('booking_saas')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Scheduled tasks
app.conf.beat_schedule = {
    'reset-monthly-limits': {
        'task': 'subscriptions.tasks.reset_monthly_limits',
        'schedule': crontab(hour=0, minute=0, day_of_month=1),  # 1st of every month at midnight
    },
    'check-expired-subscriptions': {
        'task': 'subscriptions.tasks.check_expired_subscriptions',
        'schedule': crontab(hour=1, minute=0),  # Every day at 1 AM
    },
    'send-upgrade-reminders': {
        'task': 'subscriptions.tasks.send_upgrade_reminders',
        'schedule': crontab(hour=10, minute=0, day_of_week='monday'),  # Every Monday at 10 AM
    },
}


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
