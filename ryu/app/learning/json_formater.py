import json

with open("nfp.json") as json_file:
    data = json.load(json_file)
    criteria_list = data["criteria"]
    for criteria in criteria_list:
        print("protocol : " + criteria["ip-proto"])

    path = data["rendered_path"]
    element  = path[0]
    print(path[0]["in_port"])
    print("nfp id : "+data["nfp_id"])