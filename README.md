Example Filebeat filebeat.yml:
```
filebeat.prospectors:
- input_type: log

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    #- /var/log/*.log
    #- c:\programdata\elasticsearch\logs\*
    - C:\My documents\Django-Python_projects\Sniffer-IP\Logs\ble_packets*.log
    - C:\My documents\Django-Python_projects\Sniffer-IP\Logs\ble_service*.log
    - C:\My documents\Django-Python_projects\Sniffer-IP\Logs\scheduler*.log
  json.keys_under_root: true
  json.add_error_key: true
  json.overwrite_keys: true


#-------------------------- Elasticsearch output ------------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["http://93.103.95.81:9200"]
  template.name: "filebeat"
  template.path: "filebeat.template.json"
  template.overwrite: false
  #pipeline: ble-pipeline
  

  # Optional protocol and basic auth credentials.
  #protocol: "https"
  #username: "elastic"
  #password: "changeme"
```