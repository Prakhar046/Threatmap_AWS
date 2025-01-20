import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view
from pymongo import MongoClient
from django.http import JsonResponse
from .consumers import *
import traceback

# MongoDB Connection
client = MongoClient('mongodb://db:27017/')  # Adjust MongoDB connection string if necessary
db = client['threatdata']  # Your MongoDB database name
threat_data = db['incidents']  # Your MongoDB collection name

# AlienVault API details
ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ALIENVAULT_HEADERS = {
    "Content-Type": "application/json",
    "X-OTX-API-KEY": "69f1dedb710f26c79f0cbdb238aee025a5758d8d918b8134e916d7337eea556c"  # Replace with your actual AlienVault API key
}

#@api_view(['GET'])
def fetch_incidents_and_store(request=None):
    if request is None:
        print("No request object provided, running as a background task.")
        
    """Fetch incidents from AlienVault and store them in MongoDB."""
    try:

        # Always start from page 1
        page = 1

        while True:
            # Prepare parameters for the request
            ALIENVAULT_PARAMS = {'page': page}

            # Fetch data from AlienVault
            response = requests.get(ALIENVAULT_API_URL, headers=ALIENVAULT_HEADERS, params=ALIENVAULT_PARAMS)
            print(f"AlienVault Status Code for page {page}: {response.status_code}")

            if response.status_code != 200:
                return Response({"error": f"AlienVault API returned status code {response.status_code}"}, status=response.status_code)

            try:
                data = response.json()
            except ValueError:
                print("Error parsing JSON from AlienVault.")
                return Response({"error": "Failed to parse AlienVault response as JSON."}, status=500)

            # Check if there's any result
            if not data.get('results'):
                print("No more data available.")
                return Response({"message": "No more data available."}, status=200)

            # Extract relevant incident data
            incidents = [
                {
                    'id': incident.get('id'),
                    'incident_name': incident.get('name'),
                    'date': incident.get('created'),  # Assuming 'created' is the date field
                    'description': incident.get('description'),
                    'affected_zones': incident.get('targeted_countries') or 'Unknown',  # Provide 'Unknown' if empty or None
                    'incidentlevel': incident['tlp'],
                    'status': 'Active' if incident['public'] == 1 else 'Inactive',
                    'reportedby': incident['author_name']  # Assuming 'created_by' corresponds to reported by
                }
                for incident in data['results']
            ]

            # Check for duplicates and store unique incidents
            new_incidents = []  # List for storing new incidents
            for incident in incidents:
                if threat_data.count_documents({'id': incident['id']}) == 0:  # Check if the incident already exists
                    new_incidents.append(incident)  # Add to new incidents if not found

            # Step to store unique incidents into MongoDB
            if new_incidents:
                threat_data.insert_many(new_incidents)  # Insert unique incidents into MongoDB

                # Send WebSocket notifications with new incidents
                for incident in new_incidents:
                    # Remove fields you don't want to send in the WebSocket update 
                    incident.pop('id', None) 
                    incident.pop('incidentlevel', None)
                    incident.pop('reportedby', None)
                    incident['_id'] = str(incident['_id'])
                    push_incident_update(incident)  # Notify WebSocket clients about the new incidents

                return Response({"message": "Data successfully inserted into MongoDB.", "current_page": page}, status=200)

            # If no new incidents, move to the next page
            print(f"No new incidents found on page {page}, moving to next page.")
            page += 1  # Move to the next page

    except Exception as e:
        print(f"Error: {e}\nTraceback: {traceback.format_exc()}")
        return Response({"error": str(e)}, status=400)





def display_incidents(request):
    """Fetch and return the latest threat data as JSON."""
    try:
        # Fetch the most recent threat data, excluding the '_id' field
        data_from_db = list(threat_data.find({}, {'_id': 0}).sort('_id', -1))
        return JsonResponse(data_from_db, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
