# from __future__ import absolute_import, unicode_literals  # For compatibility with older Python versions
# import os
# from celery import Celery
# from celery.schedules import crontab


# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatmap.settings')  # Update with your project name
# os.environ.setdefault('FORKED_BY_MULTIPROCESSING', '1')

# app = Celery('threatmap')
# app.config_from_object('django.conf:settings', namespace='CELERY')
# app.autodiscover_tasks(['threatapp'])  # Update with your app name

# app.conf.beat_schedule = {
#     'fetch-every-10-minutes': {
#         'task': 'threatapp.tasks.periodic_fetch_and_store',  # Full path to the task
#         'schedule': crontab(minute='*/1'),  # Every 10 minutes
#     },
# }









# app.conf.beat_schedule = {
#     'fetch-every-10-minutes': {
#         'task': 'threatapp.tasks.periodic_fetch_and_store',  # Full path to the task
#         'schedule': crontab(minute='*/1'),  # Every 10 minutes
#     },
#     'fetch-top5-country-data-daily': {
#         'task': 'threatapp.tasks.periodic_fetch_top5_country_data',
#         'schedule': crontab(minute='*/2'),
#         #'schedule': crontab(hour=0, minute=0),  # Run once daily at midnight
#     },
# }








from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from kombu import Queue

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatmap.settings')
os.environ.setdefault('FORKED_BY_MULTIPROCESSING', '1')

app = Celery('threatmap')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(['threatapp'])  # Update with your app name

# Define separate queues
app.conf.task_queues = (
    Queue('concurrent_tasks', routing_key='concurrent.#'),
    Queue('single_tasks', routing_key='single.#'),
    Queue('incident_tasks', routing_key='incident.#' )
)

# Define task routing
app.conf.task_routes = {
    'threatapp.tasks.fetch_daily_data_task': {'queue': 'single_tasks'},
    'threatapp.tasks.fetch_top5_country_data_task': {'queue': 'single_tasks'},
    'threatapp.tasks.fetch_top5_industry_data_task': {'queue': 'single_tasks'},
    'threatapp.tasks.fetch_threat_and_store_task': {'queue': 'concurrent_tasks'},
    'threatapp.tasks.fetch_incidents_and_store_task': {'queue': 'incident_tasks'},
    'threatapp.tasks.periodic_fetch_and_store': {'queue': 'concurrent_tasks'},
}


# Celery Beat schedule
from celery.schedules import crontab

app.conf.beat_schedule = {
    'fetch-every-1-minutes': {
        'task': 'threatapp.tasks.periodic_fetch_and_store',  # Full path to the task
        'schedule': crontab(minute='*/1'),  # Every 10 minutes
    },
}
