import ipaddress
from urllib.parse import quote

RDAP_DOMAIN = "https://rdap.org/domain/{}"
RDAP_IP = "https://rdap.org/ip/{}"
DOH = "https://dns.google/resolve?name={}&type={}"
CRT = "https://crt.sh/?q=%25.{}&output=json"


def rdap_domain_url(d): return RDAP_DOMAIN.format(d)
def rdap_ip_url(ip): return RDAP_IP.format(ip)
def doh_url(name, rtype): return DOH.format(quote(name), rtype)
def crt_url(d): return CRT.format(d)


def cymru_origin_name(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    return a.reverse_pointer[:-len(".ip6.arpa")] + ".origin6.asn.cymru.com"


def cymru_asn_name(asn): return f"AS{asn}.asn.cymru.com"
def ptr_name(ip): return ipaddress.ip_address(ip).reverse_pointer
