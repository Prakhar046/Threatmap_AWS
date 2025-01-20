from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
from datetime import datetime

# Connect to MongoDB
client = MongoClient("mongodb://db:27017/")
db = client["threatdata"]  # Replace with your database name
collection = db["new"]  # Replace with your collection name

@csrf_exempt
def filter_by_dates(request):
    try:
        # Extract query parameters
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
        
        # Ensure both dates are provided
        if not start_date or not end_date:
            print("error: Please provide both start_date and end_date.")
            return JsonResponse({"error": "Please provide both start_date and end_date."}, status=400)
        
        # Convert dates to datetime objects
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d")
        
        # Query MongoDB for documents within the date range
        filtered_data = list(collection.find({
            "reported": {
                "$gte": start_date.isoformat(),
                "$lte": end_date.isoformat()
            }
        }, {"_id": 0,"source":0,"destination":0,"category":0,"attack_details":0,"reported":0}))  # Exclude _id from results

        return JsonResponse({"data": filtered_data}, safe=False, status=200)
    
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
