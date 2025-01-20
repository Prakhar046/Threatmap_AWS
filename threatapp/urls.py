from django.urls import path
from .views import *
from .views_2 import *
from .views_3 import *
from .views_incidents import *
from .views_filter_dates import *
from .views_Country_Trend import *
from .views_heatmap import *
from .views_Threat_Count import *
from .To_see_total_threatnames import *

urlpatterns = [
    path('fetch_top5_threats/', fetch_top5_country_data, name='fetch_threat_data'),
    path('display_top5_threats/', display_threat_data, name='display_threat_data'),
    path('fetch/',fetch_threat_and_store),
    path('display/',display_threats),
    path('a/<str:start_date>/<str:end_date>/',fetch_daily_data),
    path('incidents/', fetch_incidents_and_store ),
    path('dis_inci/', display_incidents ),
    path('filter_date/', filter_by_dates),
    path('trend/', country_attack_trends_view),
    path('heatmap/', get_attack_count_view),
    path('threat_count/', threat_name_count_view),
    path('total_threats/', To_see_total_threat_names )
]