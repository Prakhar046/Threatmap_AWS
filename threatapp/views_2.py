import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view
from pymongo import MongoClient
from django.http import JsonResponse
from datetime import datetime, timedelta
from .consumers import *
import traceback, pytz
import numpy as np

# MongoDB Connection
client = MongoClient('mongodb://db:27017/')  # Adjust MongoDB connection string if necessary
db = client['threatdata']  # Your MongoDB database name
threat_data = db['new']  # Your MongoDB collection name
config = db['config']  # A separate collection to store configurations like last checked time

# AlienVault Pulse IDs (Add as many as you like)
ALIENVAULT_PULSES = [
    "6421c1a0fd8452595dc148fa",
    "66794486bda6c3cf8823c604",
    "60ece5998a5b54a5ffe75cb4",
    "5a7e3e70c44e7b48947593a7",
    "66c74422b99d3b24bb2c574b",
    "606d75c11c08ff94089a9430",
]

# AlienVault API details
#ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/670324881a9d7f8c4e483561"
#ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/60ece5998a5b54a5ffe75cb4" # this pulse was the last working pulse
ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/"
ALIENVAULT_HEADERS = {
    "Content-Type": "application/json",
    "X-OTX-API-KEY": "69f1dedb710f26c79f0cbdb238aee025a5758d8d918b8134e916d7337eea556c"  # AlienVault API key
}

# CrowdSec API details
CROWDSEC_API_URL = "https://cti.api.crowdsec.net/v2/smoke/"
CROWDSEC_HEADERS = {
    "Content-Type": "application/json",
    #"x-api-key": "pBs9iBKd3F4pTXH55LlagabqOUiHpAqy6x4DG5uh"  # CrowdSec API key
    "x-api-key": 'FnNp1xLZhe1FJREmscGdw6N97Fc5Gtri1ZG5NFfB'
    #"x-api-key": "OfFBV7VBAu6fogXAKNsG28oTGNTxLkmN6PNeU3zP"
}



#@api_view(['GET'])
def fetch_threat_and_store(request=None):
    if request is None:
        print("No request object provided, running as a background task.")
        
    # Fetch IPs from AlienVault and check them in CrowdSec, then store the results in MongoDB.
    try:
        # Step 1: Check last fetch time from MongoDB
        last_checked = config.find_one({"config_name": "last_checked"})
        current_time = datetime.now()

        # Step 2: Fetch data from each AlienVault pulse
        for pulse_id in ALIENVAULT_PULSES:
            alienvault_response = requests.get(f"{ALIENVAULT_API_URL}{pulse_id}", headers=ALIENVAULT_HEADERS)
            print(f"AlienVault Status Code for Pulse {pulse_id}: {alienvault_response.status_code}")

            if alienvault_response.status_code != 200:
                #return Response({"error": f"AlienVault API returned status code {alienvault_response.status_code}"}, status=alienvault_response.status_code)
                print(f"Failed to fetch data fro pulse {pulse_id}")
                continue
            
            try:
                alienvault_data = alienvault_response.json()  # Parse AlienVault response as JSON
            except ValueError:
                print("Error parsing JSON from AlienVault for pulse {pulse_id}.")
                #return Response({"error": "Failed to parse AlienVault response as JSON."}, status=500)
                continue

            # Step 3: Extract the IPv4 addresses from AlienVault data
            ip_addresses = [entry['indicator'] for entry in alienvault_data.get('indicators', []) if entry.get('type') == 'IPv4']
            
            # convert the list of IPs to Numpy array for better performance with large datasets
            ip_array = np.array(ip_addresses)
            
            # If no IPs are found, exit early
            if len(ip_array) == 0:
                print("No IP addresses found in AlienVault response.")
                continue
                #return Response({"message": "No IP addresses found in AlienVault response."}, status=200)

            selected_ips = ip_array[-1:-4:-1] # Example: select the last 2 IPs
            
            results_to_store = []  # List to store results for MongoDB

            # Loop through the IP addresses and check each one in CrowdSec
            #for ip in ip_addresses[-33:-34:-1]:
            for ip in selected_ips:
                print(f"Checking IP address: {ip}")

                # Step 4: Check the IP in CrowdSec
                crowdsec_response = requests.get(f"{CROWDSEC_API_URL}{ip}", headers=CROWDSEC_HEADERS)
                print(f"CrowdSec Status Code for IP {ip}: {crowdsec_response.status_code}")

                if crowdsec_response.status_code != 200:
                    #print(f"Crowdsec Error Response for IP {ip}: {crowdsec_response.text}")
                    continue  # Skip to the next IP if there was an error

                try:
                    crowdsec_data = crowdsec_response.json()
                    #print(f"CrowdSec response data for IP {ip}: {crowdsec_data}")

                except ValueError:
                    #print(f"Error parsing JSON from CrowdSec for IP {ip}")
                    continue  # Skip to the next IP if there was an error parsing

                # Extract relevant data from CrowdSec response
                source_country =  crowdsec_data.get('location', {}).get('country', 'Unknown')
                country_latitude = crowdsec_data.get('location', {}).get('latitude', 'N/A')
                country_longitude = crowdsec_data.get('location', {}).get('longitude', 'N/A')
                reputation = crowdsec_data.get('reputation', 'Unknown')
                confidence = crowdsec_data.get('confidence', 'Unknown')
                #behaviors = [behavior['label'] for behavior in crowdsec_data.get('behaviors', [])]
                attack_details = [attack['label'] for attack in crowdsec_data.get('attack_details', [])]
                reported =  crowdsec_data.get('history', {}).get('last_seen', 'Unknown')
                
                # If we want a single entry from the behaviors section then use this line and comment the first one
                behaviors = [crowdsec_data.get('behaviors', [{}])[0].get('label')] if crowdsec_data.get('behaviors') else []
                
                # Fetch full Source_Country name
                try:
                    response = requests.get(f"https://restcountries.com/v3.1/alpha/{source_country}")
                    source_country = response.json()[0]["name"]["common"] if response.ok else source_country
                except Exception as e:
                    source_country = source_country  # Keep the short form in case of an exception
                    
                
                
                # Step 5: Handle multiple attacked countries separately
                target_countries = crowdsec_data.get('target_countries', {})
                attacked_countries = [country for country in target_countries.keys()]
                
                for attacked_country in attacked_countries:
                    # Check if the record already exists
                    existing_record = threat_data.find_one({
                        'ip_address': ip,
                        'Destination_Name': attacked_country
                    })

                    # Fetch the latitude and longitude using the country code
                    try:
                        restcountries_response = requests.get(f"https://restcountries.com/v3.1/alpha/{attacked_country}")
                        if restcountries_response.ok:
                            restcountries_data = restcountries_response.json()
                            attacked_country_full_name = restcountries_data[0]["name"]["common"]
                            country_coordinates = restcountries_data[0].get("latlng", [None, None])
                            dest_lat, dest_lon = country_coordinates[0], country_coordinates[1]
                        else:
                            attacked_country_full_name = attacked_country
                            print(f"RestCountries Error for {attacked_country}: {restcountries_response.status_code}")
                            dest_lat, dest_lon = None, None  # Fallback if the API call fails
                    except Exception as e:
                        attacked_country_full_name = attacked_country
                        print(f"RestCountries API Exception: {e}")
                        dest_lat, dest_lon = None, None  # Fallback in case of an exception

                    # Create a threat record
                    threat_info = {
                        'ip_address': ip,
                        'source_Name': source_country,
                        'source': [country_latitude, country_longitude],
                        'Destination_Name': attacked_country_full_name,
                        'destination': [dest_lat, dest_lon],
                        'reported': reported,
                        'Category': reputation,
                        'Threat_Name': behaviors,
                        'Threat_Level': confidence,
                        'attack_details': attack_details,
                    }

                    # Send to WebSocket clients regardless of database storage
                    push_threat_update(threat_info)

                    # Add to `results_to_store` only if it's not a duplicate
                    if not existing_record:
                        #results_to_store.append(threat_info)
                        threat_data.insert_one(threat_info)
                        
                        
                    else:
                        print("No data stored")

        # Config will be updated at last when all the data is fetched from all pulse in loop
        config.update_one({"config_name": "last_checked"}, {"$set": {"time": current_time}}, upsert=True)
        print("updated config")
     
    #**********IF U WANT TO STORE DATA AT LAST THEN USE THE BELOW CODE********
    
    
        # # Step 6: Store the combined data into MongoDB
        # if results_to_store:
        #     print(f"Inserting {len(results_to_store)} new records into MongoDB")
        #     threat_data.insert_many(results_to_store)
        #     # Update last checked time in MongoDB
        #     config.update_one({"config_name": "last_checked"}, {"$set": {"time": current_time}}, upsert=True)
        #     print("updated config")
        #     #return Response({"message": "Data successfully inserted into MongoDB."}, status=200)
        #     print("successful")
        # else:
        #     print("No data stored")
        #     return Response({"message": "No new data to insert."}, status=200)

    except Exception as e:
        print(f"Error: {e}\nTraceback: {traceback.format_exc()}")
        return Response({"error": str(e)}, status=400)



def display_threats(request):
    """Fetch and return the latest threat data as JSON."""
    try:
        # Fetch the most recent threat data, excluding the '_id' field
        data_from_db = list(threat_data.find({}, {'_id': 0}).sort('_id', -1))
        return JsonResponse(data_from_db, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
