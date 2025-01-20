from django.http import JsonResponse
from pymongo import MongoClient
from datetime import datetime, timedelta

def country_attack_trends_view(request):
    country = request.GET.get('country')  # Country code from frontend
    print(f"Country: {country}")
    
    period = request.GET.get('period', 'monthly')  # Optional: period (daily, weekly, monthly)
    print(f"Period: {period}")
    
    if not country:
        print("error: Country parameter is required.")
        return JsonResponse({"error": "Country parameter is required."}, status=400)

    client = MongoClient('mongodb://db:27017/')  # Update with your DB URI
    db = client['threatdata']
    collection = db['new']

    # Define the date range for trend analysis
    now = datetime.utcnow()
    print(f"Current Time: {now}")
    
    if period == 'daily':
        start_date = now - timedelta(days=7)  # Last 30 days for daily trend
    elif period == 'weekly':
        start_date = now - timedelta(weeks=4)  # Last 4 weeks for weekly trend
    else:  # Default to 'monthly' trend
        start_date = now - timedelta(weeks=12)  # Last 12 weeks for monthly trend
    
    print(f"Start Date: {start_date}")
    
    # Convert start_date to string format
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S+00:00')
    #print(f"Start Date String: {start_date_str}")

    # Aggregate to find the number of attacks over time
    pipeline = [
    {
        "$match": {
            "$or": [
                #{"source_Name": country},  # Attacks from this country
                {"Destination_Name": country}  # Attacks to this country
            ],
            "reported": {"$gte": start_date_str}  # Filter by start date
        }
    },
    {
        "$addFields": {
            "reported_date": {
                "$dateFromString": {
                    "dateString": "$reported",  # Convert 'reported' to Date
                    "format": "%Y-%m-%dT%H:%M:%S+00:00"  # Adjust the format if needed
                }
            }
        }
    },
    {
        "$project": {
            "reported_date": {
                "$dateToString": {"format": "%Y-%m-%d", "date": "$reported_date"}  # Now use the newly converted date
            }
        }
    },
    {
        "$group": {
            "_id": "$reported_date",
            "attack_count": {"$sum": 1}
        }
    },
    {
        "$sort": {"_id": 1}  # Sort by date
    }
]


    result = list(collection.aggregate(pipeline))
    #print(f"Aggregation Result: {result}")

    if not result:
        print("error: No data found for the specified country.")
        return JsonResponse({"error": "No data found for the specified country."}, status=404)

    # Format the response to return the trend data
    trends = [{"date": trend["_id"], "attack_count": trend["attack_count"]} for trend in result]

    return JsonResponse({"country": country, "trend_data": trends})
