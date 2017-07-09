import json
from requests.auth import HTTPBasicAuth
import requests

from Project.config import ELASTIC_USERNAME, ELASTIC_PASSWORD, ELASTIC_DOMAIN_NAME

#Delete old documents CAUTION!!!
print (requests.delete('https://blesniffer.ddns.net:9200/filebeat-*', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)

#print (requests.put('https://blesniffer.ddns.net:9200/_xpack/security/user/elastic/_password',
#                     data=json.dumps({'password':ELASTIC_PASSWORD}),
#                    auth=HTTPBasicAuth(ELASTIC_USERNAME, "changeme")).text)
#

set_auth_for_filebeat = {
    "cluster": ["manage_index_templates", "monitor"],
    "indices": [
        {
            "names": [ "filebeat-*"],
            "privileges": ["read","write","create_index"]
        }
    ]
}
set_auth_for_metricbeat = {
    "cluster": ["manage_index_templates", "monitor"],
    "indices": [
        {
            "names": [ "metricbeat-*"],
            "privileges": ["read","write","create_index"]
        }
    ]
}

auth_filebeat = {
    "password" : ELASTIC_PASSWORD,
    "roles" : [ "filebeat_writer"],
    "full_name" : "Internal Filebeat User"
}

auth_metricbeat = {
    "password" : ELASTIC_PASSWORD,
    "roles" : [ "metricbeat_writer"],
    "full_name" : "Internal Metricbeat User"
}

print (requests.put('https://blesniffer.ddns.net:9200/_xpack/security/user/kibana/_password',
                    data=json.dumps({'password':"kibanasniffer"}),
                    auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)

#print (requests.post('https://blesniffer.ddns.net:9200/_xpack/security/role/filebeat_writer', data=json.dumps(set_auth_for_filebeat), auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)
#print (requests.post('https://blesniffer.ddns.net:9200/_xpack/security/role/metricbeat_writer', data=json.dumps(set_auth_for_filebeat), auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)
#print (requests.post('https://blesniffer.ddns.net:9200/_xpack/security/user/elastic', data=json.dumps(auth_filebeat), auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)
#print (requests.post('https://blesniffer.ddns.net:9200/_xpack/security/user/elastic', data=json.dumps(auth_metricbeat), auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)
#Pipeline setup
data = {
    "description" : "parse timestamp and update @timestamp",
    "processors" : [
        {
            "date" : {
                "field" : "timestamp",
                "formats" : ["yyyy-MM-dd'T'HH:mm:ss.SSSZZ"]
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


change_to_date = {
    "properties": {
        "timestamp": {
            "type":   "date"
        }
    }
}
change_client_date = {
    "properties": {
        "timestamp": {
            "type":   "date"
        }
    }
}



timestamp_since_to_date = {
    "mappings": {
        "timestamp": {
            "type": "date"
        },
        "client": {
            "properties": {
                "online_since": {
                    "type": "date"
                }
            }
        }

    }
}

#print(requests.put('https://blesniffer.ddns.net:9200/filebeat-*/_mapping/timestamp',  auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD),
#data=json.dumps(change_to_date)).text)
#print(requests.put('https://blesniffer.ddns.net:9200/filebeat-*/_mapping/client.online_since', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD),
#                   data=json.dumps(change_to_date)).text)
#print(requests.put('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat/_mapping/packet', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD), data=json.dumps(change_to_date)))
#print(requests.put('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD), data=json.dumps(timestamp_since_to_date)).text)


#print(requests.get('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat*/_mapping/', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)

mapping_json = {
    "mappings":{
        "_default_": {
            "_meta": {
                "version": "5.4.0"
            },
            "_all": {
                "norms": False
            },
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "ignore_above": 1024,
                            "type": "keyword"
                        }
                    }
                }
            ],
            "date_detection": False,
            "properties": {
                "@timestamp": {
                    "type": "date"
                },
                "beat": {
                    "properties": {
                        "hostname": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "version": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "error": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "fields": {
                    "type": "object"
                },
                "fileset": {
                    "properties": {
                        "module": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "input_type": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "message": {
                    "type": "text",
                    "norms": False
                },
                "meta": {
                    "properties": {
                        "cloud": {
                            "properties": {
                                "availability_zone": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "instance_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "machine_type": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "project_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "provider": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "region": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                }
                            }
                        }
                    }
                },
                "offset": {
                    "type": "long"
                },
                "read_timestamp": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "source": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "system": {
                    "properties": {
                        "auth": {
                            "properties": {
                                "groupadd": {
                                    "properties": {
                                        "gid": {
                                            "type": "long"
                                        },
                                        "name": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        }
                                    }
                                },
                                "hostname": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "message": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "pid": {
                                    "type": "long"
                                },
                                "program": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "ssh": {
                                    "properties": {
                                        "dropped_ip": {
                                            "type": "ip"
                                        },
                                        "event": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "geoip": {
                                            "properties": {
                                                "city_name": {
                                                    "type": "keyword",
                                                    "ignore_above": 1024
                                                },
                                                "continent_name": {
                                                    "type": "keyword",
                                                    "ignore_above": 1024
                                                },
                                                "country_iso_code": {
                                                    "type": "keyword",
                                                    "ignore_above": 1024
                                                },
                                                "location": {
                                                    "type": "geo_point"
                                                },
                                                "region_name": {
                                                    "type": "keyword",
                                                    "ignore_above": 1024
                                                }
                                            }
                                        },
                                        "ip": {
                                            "type": "ip"
                                        },
                                        "method": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "port": {
                                            "type": "long"
                                        },
                                        "signature": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        }
                                    }
                                },
                                "sudo": {
                                    "properties": {
                                        "command": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "error": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "pwd": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "tty": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "user": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        }
                                    }
                                },
                                "user": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "useradd": {
                                    "properties": {
                                        "gid": {
                                            "type": "long"
                                        },
                                        "home": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "name": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "shell": {
                                            "type": "keyword",
                                            "ignore_above": 1024
                                        },
                                        "uid": {
                                            "type": "long"
                                        }
                                    }
                                }
                            }
                        },
                        "syslog": {
                            "properties": {
                                "hostname": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "message": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "pid": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "program": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "timestamp": {
                                    "type": "date"
                                }
                            }
                        }
                    }
                },
                "tags": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "type": {
                    "type": "keyword",
                    "ignore_above": 1024
                }
            }
        },
        "log": {
            "_meta": {
                "version": "5.4.0"
            },
            "_all": {
                "norms": False
            },
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "ignore_above": 1024,
                            "type": "keyword"
                        }
                    }
                }
            ],
            "date_detection": False,
            "properties": {
                "@timestamp": {
                    "type": "date"
                },
                "beat": {
                    "properties": {
                        "hostname": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "version": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "client": {
                    "properties": {
                        "host": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "is_active": {
                            "type": "boolean"
                        },
                        "local_IP": {
                            "type": "ip",
                        },
                        "online_since": {
                            "type": "date",
                            "format" : "yyyy-MM-dd'T'HH:mm:ss.SSSZZ"
                        },
                        "public_IP": {
                            "type": "ip",
                        },
                        "software_version": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "error": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "fields": {
                    "type": "object"
                },
                "fileset": {
                    "properties": {
                        "module": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "input_type": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "levelname": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "message": {
                    "type": "text",
                    "norms": False
                },
                "meta": {
                    "properties": {
                        "cloud": {
                            "properties": {
                                "availability_zone": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "instance_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "machine_type": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "project_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "provider": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "region": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                }
                            }
                        }
                    }
                },
                "name": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "offset": {
                    "type": "long"
                },
                "read_timestamp": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "source": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "tags": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "timestamp": {
                    "type": "date",
                    "format" : "yyyy-MM-dd'T'HH:mm:ss.SSSZZ"
                },
                "type": {
                    "type": "keyword",
                    "ignore_above": 1024
                }
            }
        }
    }
}


multi_index_mapping = {
"properties": {
                "@timestamp": {
                    "type": "date"
                },
                "beat": {
                    "properties": {
                        "hostname": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "version": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "client": {
                    "properties": {
                        "host": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "is_active": {
                            "type": "boolean"
                        },
                        "local_IP": {
                            "type": "ip",
                        },
                        "online_since": {
                            "type": "date",
                            "format" : "yyyy-MM-dd'T'HH:mm:ss.SSSZZ"
                        },
                        "public_IP": {
                            "type": "ip",
                        },
                        "software_version": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "error": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "fields": {
                    "type": "object"
                },
                "fileset": {
                    "properties": {
                        "module": {
                            "type": "keyword",
                            "ignore_above": 1024
                        },
                        "name": {
                            "type": "keyword",
                            "ignore_above": 1024
                        }
                    }
                },
                "input_type": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "levelname": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "message": {
                    "type": "text",
                    "norms": False
                },
                "meta": {
                    "properties": {
                        "cloud": {
                            "properties": {
                                "availability_zone": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "instance_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "machine_type": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "project_id": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "provider": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                },
                                "region": {
                                    "type": "keyword",
                                    "ignore_above": 1024
                                }
                            }
                        }
                    }
                },
                "name": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "offset": {
                    "type": "long"
                },
                "read_timestamp": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "source": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "tags": {
                    "type": "keyword",
                    "ignore_above": 1024
                },
                "timestamp": {
                    "type": "date",
                    "format" : "yyyy-MM-dd'T'HH:mm:ss.SSSZZ"
                },
                "type": {
                    "type": "keyword",
                    "ignore_above": 1024
                }
            }
        }



#print(requests.put('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat*/_settings', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD), data=json.dumps({"index.mapper.dynamic":False})).text)
#print(requests.delete('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD)).text)
#print(requests.put('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD), data=json.dumps(mapping_json)).text)
#print(requests.put('https://'+ELASTIC_DOMAIN_NAME+':9200/filebeat-*/_mapping/log', auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD), data=json.dumps(multi_index_mapping)).text)