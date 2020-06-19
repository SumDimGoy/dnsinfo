import dnsinfo
nameservers = None

def test_dig():
    global nameservers
    d = dnsinfo.probe('sources.org')
    nameservers = d['sources.org.']['NS']

def test_dnssec():
    global nameservers
    return dnsinfo.dnssec_check('sources.org', nameservers=nameservers)
