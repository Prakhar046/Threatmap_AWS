# from celery import shared_task, group
# from threatapp.views import*
# from threatapp.views_2 import *
# from threatapp.views_3 import *
# from threatapp.views_4 import *
# from threatapp.views_incidents import *

# import time

# @shared_task
# def periodic_fetch_and_store():
    
#     try:
#         """A Celery task to periodically fetch and store data."""
#         print("Fetching the Daily Attacks")
#         fetch_daily_data()
        
#         print("Fetching the Top5_Country_Attacks")
#         #fetch_top5_country_data() 
        
#         print("Fetching the Top5_Industry_Attacks")
#         #top_attacked_industries()
    
#         print("Fetching the Threats")
#         fetch_threat_and_store()
        
#         print("Fetching the Incidents")
#         #fetch_incidents_and_store()

#         #time.sleep(1)
        
#     except Exception as e:
#         print(f"An error occurred: {e}")
        
        
        
        
        
# @shared_task
# def periodic_fetch_top5_country_data():
    
#     try:
#     # This will call the view function directly
#         # print("Fetching the Top5_Country_Attacks")
#         # fetch_top5_country_data() 
        
#         # print("Fetching the Top5_Industry_Attacks")
#         # top_attacked_industries()
#         pass
    
    
#     except Exception as e:
#         print(f"An error occurred: {e}")       
    
    
        







from celery import shared_task, group
from threatapp.views import *
from threatapp.views_2 import *
from threatapp.views_3 import *
from threatapp.views_4 import *
from threatapp.views_incidents import *

@shared_task
def fetch_daily_data_task(queue='single_tasks'):
    """Task to fetch and store daily attack data."""
    print("Fetching the Daily Attacks")
    fetch_daily_data()

@shared_task
def fetch_top5_country_data_task(queue='single_tasks'):
    """Task to fetch and store top 5 country attack data."""
    print("Fetching the Top5 Country Attacks")
    fetch_top5_country_data()

@shared_task
def fetch_top5_industry_data_task(queue='single_tasks'):
    """Task to fetch and store top 5 industry attack data."""
    print("Fetching the Top5 Industry Attacks")
    top_attacked_industries()

@shared_task
def fetch_threat_and_store_task(queue='concurrent_tasks'):
    """Task to fetch and store threat data."""
    print("Fetching the Threats")
    fetch_threat_and_store()

@shared_task
def fetch_incidents_and_store_task(queue='incident_tasks'):
    """Task to fetch and store incidents data."""
    print("Fetching the Incidents")
    fetch_incidents_and_store()

@shared_task
def periodic_fetch_and_store(queue='concurrent_tasks'):
    try:
        """A Celery task to periodically fetch and store data."""

        print("Starting parallel data fetch tasks...")

        # Using a group to run tasks in parallel
        task_group = group(
            fetch_daily_data_task.s(),  # Corrected to use the Celery task
            fetch_top5_country_data_task.s(),
            fetch_top5_industry_data_task.s(),
            fetch_threat_and_store_task.s(),
            fetch_incidents_and_store_task.s()
        )

        # Apply the task group
        task_group.apply_async()
        # result = task_group.apply_async()

        # # Optionally, wait for the result (you can remove this if you don't need to wait)
        # result.get()  # This will wait until all tasks are completed

        print("Data fetch tasks completed.")

    except Exception as e:
        print(f"An error occurred: {e}")

