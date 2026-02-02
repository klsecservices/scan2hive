# scan2hive

New tool for importing scan results to Hive, based on [hive-library examples](https://github.com/hexway/hive-library).

## Usage and features
uv:
```
uv run scan2hive <mode> <tool> ...args
```
not uv
```
python main.py <mode> <tool> ...args
```
help:
```
usage: scan2hive [-h] (--dry-run | --upload) {nuclei,gowitness,httpx,nmap,poseidon} ...

Tool for importing scan results to Hive

positional arguments:
  {nuclei,gowitness,httpx,nmap,poseidon}
    nuclei              Import nuclei results to Hive project. You can use JSON or JSONL formatted files
    gowitness           Import gowitness result to Hive project. Input is sqlite file
    httpx               Import httpx json result in Hive project
    nmap                Import nmap or masscan result (XML format) to Hive project
    poseidon            Import poseidon portscan json result in Hive project

options:
  -h, --help            show this help message and exit
  --dry-run             Do nothing, just show what would be done
  --upload              Upload results to Hive
```
### About mode
#### dry-run
Prints data that will be imported. Prints host per line by default. Use `-j` option to print as JSON.
#### upload
Tries to make snapshot and uploads data to a Hive server. `-s/--server`, `-p/--project` arguments are required.
scan2hive will ask you username and password after parsing input data.
### nmap and masscan
It parses only XML format and adds tag on each parsed port. Use `-m/--max-port` for false presumably positive filtering and preventing Hive UI crashes. 
```
scan2hive nmap -h
usage: scan2hive nmap [-h] -i INPUT_FILE -t TAG [-m MAX_PORTS] [--script-parsing {record,note,not_parse}]

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Input file
  -t TAG, --tag TAG     Tag, e.g. 'egress_<IP>'
  -m MAX_PORTS, --max-ports MAX_PORTS
                        Max number of ports. Default is 300
  --script-parsing {record,note,not_parse}
                        How to parse scripts. Default is record
```

### HTTPX
It parses httpx JSON or JSONL output, adds tag on each parsed port and creates note for each result.
```
scan2hive httpx -h       
usage: scan2hive httpx [-h] -i INPUT_FILE -t TAG

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Input file
  -t TAG, --tag TAG     Tag, e.g. 'egress_<IP>'
```
Note format:
```
httpx result:
"url": <data>
"title": <data>
"webserver": <data>
"final_url": <data>
"tech": <data>
```
### Gowitness
It parses data from gowitness sqlite database, adds tag on each parsed port and creates note for each result. Can upload screenshots from database (`-us` parameter): `all` - upload all screenshots, `only_200ok` - upload screenshots only for responses with status code 200.
```
scan2hive gowitness -h
usage: scan2hive gowitness [-h] -i INPUT_FILE -t TAG  [-us {no,all,only_200ok}]

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Input file
  -t TAG, --tag TAG     Tag, e.g. 'egress_<IP>'
  -us {no,all,only_200ok}, --upload-screenshots {no,all,only_200ok}
                        upload screenshots (not upload by default) (default: no
```
Note format:
```
gowitness result: 
"url": <data>
"response_code": <data>
"title": <data>
"webserver": <data>
"final_url": <data>
"tech": <data>
"cookies": <data>
```
### Nuclei
It parses nuclei JSON or JSONL output, adds tag on each parsed port. Creates one note for each ip-port-severity. 
You can filter results by severity or set template names that will not be imported.
```
scan2hive nuclei -h   
usage: scan2hive nuclei [-h] -i INPUT_FILE -t TAG [-ms {info,low,medium,high,critical}] [--ignore [IGNORE ...]]

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Input file
  -t TAG, --tag TAG     Tag, e.g. 'egress_<IP>'
  -ms {info,low,medium,high,critical}, --min-severity {info,low,medium,high,critical}
                        Minimum severity (default: info)
  --ignore [IGNORE ...]
                        List of template IDs to ignore
```
example:
```
scan2hive --dry-run nuclei -t ext_IP -i nuclei_tests.json --ignore default-apache-test-all --ignore openssh-detect --ignore apache-detect
```
Note format:
```
nuclei result. severity <severity>

===template: <template id>===
description: <template descritpion>
extracted_results: <data>
matcher_name: <data>
matched_at: <data>

extracted_results: <data>
matcher_name: <data>
matched_at: <data>

===template: <template_id>===
description: <template descritpion>
extracted_results: <data>
matcher_name: <data>
matched_at: <data>
```
### Poseidon
It parses httpx JSON output (_Download output_ for portscan task), adds tag on each parsed port.
```
scan2hive poseidon -h       
usage: scan2hive poseidon [-h] -i INPUT_FILE -t TAG

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input INPUT_FILE
                        Input file
  -t TAG, --tag TAG     Tag, e.g. 'egress_<IP>'
```