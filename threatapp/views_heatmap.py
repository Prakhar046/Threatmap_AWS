from django.http import JsonResponse
from pymongo import MongoClient
from datetime import datetime, timedelta

def get_attack_count_view(request):
    """Django view that fetches and returns attack counts with latitude and longitude as JSON."""
    
    # Get the current UTC time
    now = datetime.now()

    # Set the start and end dates as needed (change days=2 to whatever value you want)
    start_date = now - timedelta(days=2)  # Example: 2 days before the current date
    end_date = start_date + timedelta(days=2)  # End of the previous day

    # Convert to string format for MongoDB query
    start_date_str = start_date.isoformat()
    end_date_str = end_date.isoformat()

    client = MongoClient('mongodb://db:27017/')  # Update with your DB URI
    db = client['threatdata']  # Database name
    collection = db['new']  # Collection name

    # Query MongoDB for documents where 'reported' date is within the specified date range
    pipeline = [
        {
            "$match": {
                "reported": {"$gte": start_date_str, "$lte": end_date_str}  # Filter based on reported date range
            }
        },
        {
            "$group": {
                "_id": "$Destination_Name",  # Group by destination country
                "attack_count": {"$sum": 1},  # Count the number of attacks for each country
                "latitude": {"$first": "$destination"},  # Get latitude
                "longitude": {"$first": "$destination"}  # Get longitude
            }
        },
        {
            "$project": {
                "country": "$_id",  # Rename _id to country
                "intensity": "$attack_count",  # Rename attack_count to intensity
                "latitude": {"$arrayElemAt": ["$latitude", 0]},  # Extract latitude
                "longitude": {"$arrayElemAt": ["$longitude", 1]}  # Extract longitude
            }
        },
        {
            "$sort": {"intensity": -1}  # Sort by intensity (number of attacks)
        },
        # {
        #     "$limit": 2
        # }
    ]

    # Run the aggregation query
    result = list(collection.aggregate(pipeline))

    if not result:
        return JsonResponse({"error": "No data found for the specified date range."}, status=404)

    # Prepare the result with country data including intensity, latitude, and longitude
    result_data = []
    for entry in result:
        result_data.append({
            "country_name": entry["country"],
            "intensity": entry["intensity"],
            "latitude": entry["latitude"] if entry["latitude"] else None,  # Directly use latitude value
            "longitude": entry["longitude"] if entry["longitude"] else None  # Directly use longitude value
        })

    return JsonResponse(result_data, safe=False)
