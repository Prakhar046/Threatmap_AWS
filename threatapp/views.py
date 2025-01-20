from django.shortcuts import render


# Create your views here.

import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view 
from pymongo import MongoClient
from datetime import datetime, timedelta
from django.http import JsonResponse  # Import JsonResponse to return data in JSON format
from .consumers import *
import traceback

# MongoDB Connection
client = MongoClient('mongodb://db:27017/')  # Replace with your MongoDB connection string if necessary
db = client['threatdata']  # Database name
collection = db['top5_attack_data']  # Collection name


#@api_view(['GET'])
def fetch_top5_country_data(request=None):
    
    # Get current date and time
    current_time = datetime.utcnow() - timedelta(days=1)  # Current UTC time (ISO format)
    past_time = current_time - timedelta(days=1)  # Two days ago
    #print(current_time)
    
    # Convert to the format required by the API (e.g., "2024-09-20T10:22:57Z")
    date_end = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    date_start =  past_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # cloudflare api and authentication details
    api_url ="https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target"
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": "gprakhar9522@gmail.com",  
        "X-Auth-Key": "70f4b092d1d6e294c0c73cf641c3ef42f19e1"
        }
    params = {
        'dateStart': date_start,
        'dateEnd': date_end
    } 
    
    
    # try:
        
    #     #sending requests to Api(cloudflare)
    #     response = requests.get(api_url, headers=headers,params=params)
    #     response.raise_for_status()
    #     data = response.json()
    #     #print(data)
        
    # except Exception as e:
    #     print(f"Error: {e}\nTraceback: {traceback.format_exc()}")
    #     return Response({"error": str(e)}, status=400)
        
        
        
        
    # if data.get("success", False):
    #     top_attacked = data["result"]["top_0"]
    #     countryattacked_to_insert = []
            
            
    #     if not top_attacked:
    #         return Response({"error": "No threat data found in the API response"}, status=400)
        
    #     for country in top_attacked:
    #         #print(country)
    #         country_data = {
    #             'target_country_alpha2': country['targetCountryAlpha2'],
    #             'target_country_name': country['targetCountryName'],
    #             'value': country['value'],
    #             'rank': country['rank'],
    #             #'date' : datetime.now()
    #         }
    #         #print(country_data)
            
            
    #         countryattacked_to_insert.append(country_data)
    #         push_top5_country_update(country_data)
            
                
    #     if countryattacked_to_insert:
    #         threat_data.insert_many(countryattacked_to_insert)
    #         #push_top5_country_update(countryattacked_to_insert)
    #         #return Response({"message": "Data successfully inserted into MongoDB."}, status=200)
        
    #     else:
    #         return Response({"message": "No new data to insert into MongoDB."}, status=200)
        
        
        
    try:
        # Make the API request
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if not data or not data.get('success', False):
            return Response({"error": "No data received from the API or request failed"}, status=400)

        top_attacked_countries = data.get('result', {}).get('top_0', [])
        if not top_attacked_countries:
            return Response({"error": "No country data found"}, status=400)

        new_data = []
        for country in top_attacked_countries:
            country_name = country.get('targetCountryName')
            value = country.get('value')
            rank = country.get('rank')

            # Document structure for WebSocket and database
            country_document = {
                'target_country_alpha2': country.get('targetCountryAlpha2'),
                'target_country_name': country_name,
                'value': value,
                'rank': rank,
                'time': datetime.utcnow().isoformat()
            }

            # Check for existing record in the database
            existing_record = collection.find_one({
                'target_country_name': country_name,
                'value': value,
                'rank': rank
            })

            # Push update to WebSocket regardless of new or existing data
            push_top5_country_update(country_document)

            # Only add new data if not already in the database
            if not existing_record:
                new_data.append(country_document)
                print("This is APPEND function ---New Top5_Country data stored in MongoDB")

        # Insert new data into MongoDB
        if new_data:
            insert_result = collection.insert_many(new_data)
            inserted_ids = [str(inserted_id) for inserted_id in insert_result.inserted_ids]
            print("This is INSERT_MANY function ---New Top5_Country data stored in MongoDB")
            return Response({"message": "Data successfully inserted into MongoDB"}, status=201)
        else:
            return Response({"message": "No new records to insert"}, status=200)

    except requests.exceptions.HTTPError as e:
        print(f"Error response: {response.text}")
        return Response({"error": f"{response.status_code} {response.reason}: {response.text}"}, status=400)

    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}\nTraceback: {traceback.format_exc()}")
        return Response({"error": str(e)}, status=400)    



# View to render the data on the web page
def display_threat_data(request):
    # Fetch the data from MongoDB collection
    data_from_db = list(collection.find({}, {'_id': 0}).sort([('date',-1),('rank',1)]).limit(5))  # Exclude the '_id' field from display
    
    # Pass the data to the template
    #return render(request, 'threatapp/threat_display.html', {'threats': data_from_db})
    # Return the data as JSON
    return JsonResponse(data_from_db, safe=False)