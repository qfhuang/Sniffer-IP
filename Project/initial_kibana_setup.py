import json

import requests

#Delete old documents
requests.delete('http://localhost:9200/filebeat-*')


#Pipeline setup
data = {
  "description" : "parse timestamp and update @timestamp",
  "processors" : [
    {
      "date" : {
        "field" : "timestamp",
        "target_field" : "@timestamp",
        "formats" : ["yyyy-MM-dd'T'HH:mm:ss.SSSZZ"]
      }
    },
    {
      "remove": {
        "field": "timestamp"
      }
    }
  ],
  "on_failure": [
    {
      "set": {
        "field": "error.message",
        "value": "{{ _ingest.on_failure_message }}"
      }
    }
  ]
}

#print(requests.put('http://localhost:9200/_ingest/pipeline/ble-pipeline', data=json.dumps(data)))