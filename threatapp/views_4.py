import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view
from pymongo import MongoClient
from .consumers import push_top5_industry_update
from datetime import datetime, timedelta
 
client = MongoClient('mongodb://db:27017/')
db = client['threatdata']  # Database name
collection = db['top_attacked_industries']  # Change collection name for industry data
 
#@api_view(['GET'])
def top_attacked_industries(request=None):
    
    # Get current date and time
    current_time = datetime.utcnow() - timedelta(days=1)  # Current UTC time (ISO format)
    past_time = current_time - timedelta(days=1)  # Two days ago
    time = datetime.now()
    #print(current_time)
    
    # Convert to the format required by the API (e.g., "2024-09-20T10:22:57Z")
    date_end = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    date_start =  past_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
   
    api_url ='https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/industry'
 
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": "gprakhar9522@gmail.com",  
        "X-Auth-Key": "70f4b092d1d6e294c0c73cf641c3ef42f19e1"
    }
   
    params = {
        'dateStart': date_start,
        'dateEnd': date_end
    }
 
    try:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()  
        data = response.json()  
       
        if not data or not data.get('success', False):
            return Response({"error": "No data received from the API or request failed"}, status=400)
 
        industry_data = data.get('result', {}).get('top_0', [])
 
        if not industry_data:
            return Response({"error": "No industry data found"}, status=400)
 
        new_data = []
        for industry in industry_data:
            industry_name = industry.get('name')
            value = industry.get('value')
 
            existing_record = collection.find_one({
                'industry_name': industry_name,
                'value': value
            })
 
            #if not existing_record:
            # Prepare document to send to WebSocket
            industry_document = {
                    'industry_name': industry_name,
                    'value': value,
                    'time': time.isoformat()
                }
                #new_data.append(industry_document)
            
            # Call WebSocket function regardless of whether the data is new or existing
            push_top5_industry_update(industry_document)
            
            # Only add to new_data if it's not in the database
            if not existing_record:
                new_data.append(industry_document)
                print("This is APPEND function ---New Top5_Industry data stored in MongoDB")
 
        # Insert new data if available
        if new_data:
            insert_result = collection.insert_many(new_data)
            inserted_ids = [str(inserted_id) for inserted_id in insert_result.inserted_ids]
            print("This is INSERT_MANY function ---New Top5_Industry data stored in MongoDB")
            #push_top5_industry_update(new_data)
            return Response({"message": "Successful"}, status=201)
        else:
            return Response({"message": "No new records to insert"}, status=200)
 
    except requests.exceptions.HTTPError as e:
        print(f"Error response: {response.text}")
        return Response({"error": f"{response.status_code} {response.reason}: {response.text}"}, status=400)
 
    except requests.exceptions.RequestException as e:
        return Response({"error": str(e)}, status=400)
 