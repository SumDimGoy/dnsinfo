# dnsinfo #
[![Build Status](https://travis-ci.com/erraticrefresh/dnsinfo.svg?branch=master)](https://travis-ci.com/erraticrefresh/dnsinfo)

#### INTRODUCTION ####
dnsinfo is a module for Python that obtains all DNS records information for each domain part and performs dnssec validation. Built with dnspython.

### Usage ###
<hr>

#### Dig ####
```python
from dnsinfo import probe

# dictionary entries for each domain part queried
info = probe('sources.org')
```
```
>>> data['root_ns']
'192.36.148.17'

>>> info['sources.org.']
{
    'SOA': {
        'mname': 'ns4.bortzmeyer.org.',
        'rname': 'hostmaster.bortzmeyer.org.',
        'serial': 2020061200,
        'refresh': 7200,
        'retry': 3600,
        'expire': 604800,
        'default_ttl': 3600
    },
    'A': {},
    'NS': {
        'ns1.bortzmeyer.org.': '204.62.14.153',
        'ns6.gandi.net.': '217.70.177.40',
        'ns4.bortzmeyer.org.': '92.243.4.211'
    },
    'timeout': False,
    'ns_queried': '204.62.14.153',
    'TXT': [
        'Sources',
        'v=spf1 mx a:uucp.bortzmeyer.org a:central.sources.org ?all'
    ]
}
```
<br>

##### DNSSEC Validation #####
```python
from dnsinfo import dnssec_check

valid = dnssec_check('sources.org')
```
```
>>> valid
(True, <DNS message, ID 8100>)
```
