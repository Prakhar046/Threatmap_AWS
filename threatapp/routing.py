from django.urls import re_path
from threatapp.consumers import *

websocket_urlpatterns = [
    re_path('ws/threats/', ThreatConsumer.as_asgi()),             # for views_2.py
    re_path('ws/daily_threats/', DailyThreatConsumer.as_asgi()),  # for views_3.py
    re_path('ws/incident_threats/', IncidentConsumer.as_asgi()),  # for views_incidents.py
    re_path('ws/top5_country/', Top5CountryConsumer.as_asgi()),   # for views.py
    re_path('ws/top5_industry/',Top5IndustryConsumer.as_asgi()),  # for views_4.py
    re_path('ws/threat_count/',ThreatNameConsumer.as_asgi()),     # for views_Threat_Count.py
]
