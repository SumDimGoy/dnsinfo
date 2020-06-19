from logging import getLogger
from random import choice
from re import (
    compile as re_compile, IGNORECASE)
from dns import (
    message, query, dnssec, name as dns_name,
    resolver, rdatatype, rcode as dns_rcode)

logger = getLogger()
root_servers = (
    '198.41.0.4', '199.9.14.201', '192.33.4.12',
    '199.7.91.13', '192.203.230.10', '192.5.5.241',
    '192.112.36.4', '198.97.190.53', '192.36.148.17',
    '192.58.128.30', '193.0.14.129', '199.7.83.42',
    '202.12.27.33')

def parse(domain):
    """
    Split domain into queryable parts in reverse.

    Arguments:
        domain (str): full domain name

    Examples:

        >>> parse('www.google.com')
        ['.', 'com.', 'google.com.', 'www.google.com.']
    """
    parts = domain.split('.')
    parts.extend('.')
    parts.reverse()
    if '' in parts:
        parts.remove('')

    for i in range(len(parts)-1):
        if not i:
            parts[i+1] = parts[i+1]+parts[i]
            continue
        parts[i+1] = parts[i+1]+'.'+parts[i]
    return parts

# regex patterns
def ip_re(ip):
    """
    ipv4 regex pattern
    """
    pattern = re_compile(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
    match = pattern.match(ip)
    if match:
        return match.group()

def domain_re(domain):
    """
    domain regex pattern

    Examples:
        google.com
        www.google.com.
        xn--xyz.nameserver.xn--abcdef for IDN / IDN TLDs
    """
    pattern = re_compile(
        (r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
        r"+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"), IGNORECASE)
    match = pattern.match(domain)
    if match:
        return match.group()

def probe(domain):
    """
    Recursive query similar to dig+trace from a root server.

    Arguments:
        domain (str): full domain name

    Returns:
        {
            'domain': domain,
            'root_ns': ns,

            For each domain part
            (str: domain part name): {
                'SOA': {} or {
                    'mname':  (str: record mname),
                    'rname': (str: record rname),
                    'serial': (str: record serial,
                    'refresh': (int: record refresh),
                    'retry': (int: record retry),
                    'expire': (int: record expire),
                    'default_ttl': (int: record minimum)
                },
                'A': {} or {
                    For each name server in dns response
                    (str: name server name): (str: name server ip)
                },
                'NS': {} or {
                    For each name server in dns response
                    (str: name server name): (str: name server ip)
                },
                'timeout': (bool),
                'ns_queried': '(name server ip after loop)',
                'TXT': ['records', 'in', 'txt']
            }
        }

    Raises:
        ValueError: (domain, 'not a valid domain name')
    """
    results = {'domain': domain}
    if domain_re(domain):
        parts = parse(domain)
        ns = choice(root_servers)
        results['root_ns'] = ns

        for part in parts[1:]:
            results[part] = {}
            results[part] = {'SOA': {}, 'A': {}, 'NS': {}, 'timeout': False}
            name = dns_name.from_text(part)
            req = message.make_query(name, rdatatype.NS)
            req_txt = message.make_query(name, rdatatype.TXT)

            try:
                res = query.udp(req, ns, timeout=5)
                res_txt = query.udp(req_txt, ns, timeout=5)
            except dns.exception.Timeout as e:
                # if timeout, skip the response
                results[part]['timeout'] = True
                logger.log(logger.level, e)
                continue

            if res:
                if res.rcode:
                    rcode = res.rcode()
                    if rcode != dns_rcode.NOERROR:
                        if rcode == dns_rcode.NXDOMAIN:
                            e = Exception( f'{part} does not exist')
                        else:
                            e = Exception( dns_rcode.to_text(rcode))
                        logger.log(logger.level, e)
                        continue
                else:
                    e = Exception('rcode not in response')
                    logger.log(logger.level, e)
                    continue

                rrsets = None
                if res.authority:
                    rrsets = res.authority
                elif res.additional:
                    rrsets = [res.additional]
                else:
                    rrsets = res.answer

                for rrset in rrsets:
                    for rr in rrset:
                        # check for start of authority
                        if rr.rdtype == rdatatype.SOA:
                            for k in ('mname', 'rname', 'serial', 'refresh',
                            'retry', 'expire', 'minimum'):
                                results[part]['SOA'][k if k != 'minimum'\
                                else 'default_ttl'] = getattr(rr, k)

                        # check for glue records if no SOA
                        # assign name server from glue record
                        # on the parent domain to next query
                        elif rr.rdtype == rdatatype.A:
                            if ip_re(rr.items[0].address):
                                ns = rr.items[0].address
                                results[part]['A'][rr.name] = ns
                            else:
                                e = Exception(
                                    'A record ip is incorrectly formatted')
                                logger.log(logger.level,
                                    [e, rr.items[0].address])

                        # check for NS records if no A record
                        elif rr.rdtype == rdatatype.NS:
                            authority = rr.target
                            try:
                                ns = resolver.query(authority)\
                                    .rrset[0].to_text()
                                if ip_re(ns):
                                    results[part]['NS']\
                                        [authority.to_text()] = ns
                                    results[part]['ns_queried'] = ns
                                else:
                                    e = Exception(
                                        'NS record ip is incorrectly formatted')
                                    logger.log(logger.level, [e, ns])
                            except (
                            resolver.NoAnswer,
                            resolver.NoNameservers,
                            resolver.NXDOMAIN,
                            resolver.YXDOMAIN) as e:
                                logger.log(logger.level, e)
                                continue

            results[part]['TXT'] = []
            if res_txt.answer:
                # dns.query.udp returns an answer object
                for rrset in res_txt.answer:
                    for rr in rrset:
                        results[part]['TXT'].append(rr.to_text().strip('"'))
            else:
                try:
                    res_txt = resolver.query(part, 'TXT')
                except (
                resolver.NoAnswer,
                resolver.NoNameservers,
                resolver.NXDOMAIN,
                resolver.YXDOMAIN) as e:
                    logger.log(logger.level, e)
                    continue

                # dns.resolver.query returns a response.answer object
                for rrset in res_txt.response.answer:
                    for item in rrset:
                        results[part]['TXT']\
                            .append(item.to_text().strip('"'))

        # check to see if we have no SOA records after querying all parts
        if not any([
        bool(results[part]['SOA'])
        for part in results if part.endswith('.') ]):
            # skip '.' and 'com.' and dig from previous results
            for part in list(results)[2:]:
                if results[part]['NS']:
                    #if not SOA yet, choose a name server from previous ns query
                    ns = choice(list(results[part]['NS'].values()))
                    req = message.make_query(part, rdatatype.SOA)
                    res = query.udp(req, ns)
                    results[part]['ns_queried'] = ns

                    # if timeout, continue to next domain part
                    if not res:
                        continue
                    elif res.answer:
                        #soa records are only answers to queries
                        if res.answer[0].rdtype == rdatatype.SOA:
                            # in rrset [0] , in rr record [0]
                            soa = res.answer[0][0]
                            for k in ('mname', 'rname', 'serial', 'refresh',
                            'retry', 'expire', 'minimum'):
                                results[part]['SOA'][k if k != 'minimum' \
                                else 'default_ttl'] = getattr(soa, k)
        return results
    else:
        e = ValueError(domain, 'not a valid domain name')
        logger.log(logger.level, e)
        raise e

def dnssec_check(domain, nameservers=False):
    """
    Dig and use name servers from response to perform a DNSSEC validation

    Arguments:
        domain (str): domain to be validated
        nameservers (dict, optional): {name: ip} for authoritative nameservers

    Returns:
        ((bool), (response or None))

    Raises:
        AttributeError: 'NoneType' object has no attribute 'answer' (res)
        IndexError: list index out of range (res.answer)
    """

    if not nameservers:
        try:
            info = dig(domain)
            nameservers = info[domain.strip('www.')+'.']['NS']
        except Exception as e:
            raise e

    req, res, answered = None, None, False
    for k, v in nameservers.items():
        # get dns key for zone
        req = message.make_query(
            domain, rdatatype.DNSKEY, want_dnssec=True)
        res = query.udp(req, v)

        # if response code is 0
        if not res.rcode():
            if res.answer:
                # answer will have two RRSETs, DNSKEY and RRSIG
                if len(res.answer) == 2:
                    answered=True
                    break

    if answered:
        # create the dns.name object
        name = dns_name.from_text(domain)
        try:
            dnssec.validate(
                res.answer[0], res.answer[1], {name: res.answer[0]})
        except dnssec.ValidationFailure:
            # be wary and do cautious something
            return False, res
        except Exception as e:
                raise e
        else:
            # all ok, valid self signed dnssec key for domain
            return True, res
    else:
        return False, None
