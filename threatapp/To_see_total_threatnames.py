from django.http import JsonResponse
from pymongo import MongoClient

def To_see_total_threat_names(request):
    client = MongoClient('mongodb://db:27017/')
    db = client['threatdata']
    collection = db['new']
    
    # MongoDB Aggregation Pipeline
    pipeline = [
        {
            "$unwind": "$Threat_Name"
        },
        {
            "$group": {
            "_id": "$Threat_Name",
            "count": {
                "$sum": 1
            }
            }
        },
        {
            "$sort": {
            "count": -1
            }
        },
        {
            "$project": {
            "_id": 1,
            "count": 1,
            "percentage": {
                "$multiply": [
                {
                    "$divide": [
                    "$count",
                    {
                        "$sum": "$count"
                    }
                    ]
                },
                100
                ]
            }
            }
        }
        ]
    
    result = list(collection.aggregate(pipeline))
    data = [{"threat_name": item["_id"], "count": item["count"]} for item in result]
    
    return JsonResponse(data, safe=False)
