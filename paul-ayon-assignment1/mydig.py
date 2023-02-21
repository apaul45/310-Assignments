import datetime
import time
import dns.name
import dns.rdatatype
import dns.message
import dns.query
import dns.exception

root_ip = "198.41.0.4"

def dig():
    try:
        input_domain = input('Enter a domain: ')
        request_time = datetime.datetime.now()

        start = time.time()
        print("\nQUESTION SECTION:")
        response = resolver(input_domain, root_ip, dns.rdatatype.A)

        print(f'\nANSWER SECTION:\n{response.answer[0].to_text()}')
        print(f'\nQuery time: {(time.time()-start) * 1000} ms')
        print(f'WHEN: {request_time}')
    except (dns.exception.DNSException, BlockingIOError) as error:
        print(f'\nERROR: {error}')
    except AttributeError:
        print('\nThis domain could not be resolved.')

def resolver(input_domain, server_ip, rdatatype):
    input_domain = dns.name.from_text(input_domain)

    if not input_domain.is_absolute():
        input_domain = input_domain.concatenate(dns.name.root)

    request = dns.message.make_query(input_domain, rdatatype)
    response = dns.query.udp(request, server_ip)

    print(response.question[0].to_text())

    if response.answer: #Check if the most recent query 
        rdata = response.answer[0][0]
        if rdata.rdtype == dns.rdatatype.CNAME: #If query returns CNAME, recursively resolve the CNAME
            return resolver(rdata.target.to_text(), root_ip, dns.rdatatype.CNAME)
        return response

    answer = section_iterator(input_domain.to_text(), response.additional, dns.rdatatype.A) #First iterate through servers in the additional section to resolve the query
    return answer if answer else section_iterator(input_domain.to_text(), response.authority, dns.rdatatype.NS) #If servers in the additional section couldn't resolve, go through authoritative name servers

def section_iterator(input_domain, section, rdatatype):
    for rrset in section:
        for rdata in rrset:
            #Recursively resolve if the query type matches what's expected
            if rdata.rdtype == rdatatype:
                #If NS, that means authoritative servers being used to resolve, so first retrieve its ip before recursive call
                address = rdata.address if rdata.rdtype == dns.rdatatype.A else resolver(rdata.target.to_text(), root_ip, dns.rdatatype.NS)

                if address and type(address) is not str: 
                    address = address.answer[0][0].address #If NS, retrieve the name server's IP from the returned answer

                response = resolver(input_domain, address, dns.rdatatype.A) if address else None #If NS and ip couldn't be found, try next NS
                if response:
                    return response #Break out of the iterator if answer found
    return None

dig()