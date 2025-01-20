from django.http import JsonResponse
from pymongo import MongoClient

def threat_name_count_view(request):
    client = MongoClient('mongodb://db:27017/')
    db = client['threatdata']
    collection = db['new']
    
    # List of specific threat names to filter
    specific_threats = [
        'HTTP Exploit',
        'HTTP Scan',
        'SSH Bruteforce',
        'SMB/RDP bruteforce',
        'Telnet Bruteforce'
    ]

    # MongoDB Aggregation Pipeline
    pipeline = [
    {
        "$unwind": "$Threat_Name"
    },
    {
        "$group": {
            "_id": {
                "$cond": {
                    "if": {"$in": ["$Threat_Name", specific_threats]},
                    "then": "$Threat_Name",
                    "else": "Other"
                }
            },
            "count": {"$sum": 1}
        }
    },
    {
        "$addFields": {
            "sort_priority": {
                "$cond": {
                    "if": {"$eq": ["$_id", "Other"]},
                    "then": 1,
                    "else": 0
                }
            }
        }
    },
    {
        "$sort": {"sort_priority": 1, "count": -1}
    },
    {
        "$group": {
            "_id": None,
            "total": {"$sum": "$count"},
            "data": {
                "$push": {
                    "threat_name": "$_id",
                    "count": "$count"
                }
            }
        }
    },
    {
        "$unwind": "$data"
    },
    {
        "$project": {
            "_id": 0,
            "threat_name": "$data.threat_name",
            "count": "$data.count",
            "percentage": {
                "$multiply": [
                    {"$divide": ["$data.count", "$total"]},
                    100
                ]
            }
        }
    }
]

    
    result = list(collection.aggregate(pipeline))
    data = [{"threat_name": item["threat_name"], "count": item["count"], "percentage": item["percentage"]} for item in result]
    
    return JsonResponse(data, safe=False)
