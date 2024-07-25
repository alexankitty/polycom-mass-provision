import urllib3
from bs4 import BeautifulSoup
import requests
import base64
import re
import ssl

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

ctx = urllib3.util.create_urllib3_context()
ctx.set_ciphers("DEFAULT@SECLEVEL=0")
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class CustomSSLContextHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)
        
### CSV Headers
### mac,pw,servertype,serverurl,serveruser,serverpass,tries,retrywait,tagsnua

class Phone():
    # Internal class methods
    def __init__(self, propList):
        for index, prop in propList.items():
            self[index] = prop

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    # Properties
    paramKeys = keys = {'servertype': 'device.prov.serverType',
                        'serverurl': 'device.prov.serverName',
                        'serveruser': 'device.prov.user',
                        'serverpass': 'device.prov.password',
                        'tries': 'device.prov.redunAttemptLimit',
                        'retrywait': 'device.prov.redunInterAttemptDelay',
                        'tagsnua':'device.prov.tagSerialNo'}
    
    # Methods
    def auth(self):
        endpointBase = f'https://{self.ip}/'
        endpointJs = f'https://{self.ip}/js/login.js'
        self.session = requests.session()
        self.session.adapters.pop("https://", None)
        self.session.mount("https://", CustomSSLContextHTTPAdapter(ctx))
        self.basicAuth = ('Polycom', self.pw)
        authstring = bytes(f"Polycom:{self.pw}", encoding="utf-8")
        # Check if password works
        resp = self.session.get(endpointJs, verify=False)
        js = resp.text
        authType = re.search(r'type: .*', js, re.MULTILINE).group(0)
        authType = self.charReplace(["'", '"', ","], authType)
        authType = authType.replace('type: ', '')
        authType = authType.strip().lower()
        authEndpoint = authType.replace('url: ', '')
        authEndpoint = re.search(r'url: .*.htm', js, re.MULTILINE).group(0)
        authEndpoint = self.charReplace(["'", '"', ","], authEndpoint)
        authEndpoint = authEndpoint.replace('url: ', '')
        authEndpoint = endpointBase + authEndpoint.strip()
        if authType == 'get':
            resp = self.session.get(authEndpoint, auth=self.basicAuth, verify=False)
        if authType == 'post':
            resp = self.session.post(authEndpoint, auth=self.basicAuth, verify=False)
        if "INVALID" in resp.text or "Failed" in resp.text:
            return False  
        elif resp.status_code == 200:
            # return the session to simplify usage later.
            self.session.cookies = resp.cookies
            if not self.session.cookies:
                # commit cookie forgery
                self.session.cookies.set("Authorization", f"Basic {base64.b64encode(authstring).decode('ascii')}", domain=self.ip)
            return True
        return False

    def parseNames(self):
        #gotta scrape the web to find out the input name of each paramName 
        
        configKeys = {}
        endpoint = f'https://{self.ip}/provConf.htm'
        resp = self.session.get(endpoint, auth=self.basicAuth, cookies=self.session.cookies, verify=False)
        soup = BeautifulSoup(resp.text, 'xml')
        for index, key in self.paramKeys.items():
            tag = soup.find('input', {"paramName": key})
            if not tag:
                tag = soup.find('select', {"paramName": key})
            configKeys[tag.attrs['name']] = index
        return configKeys

    def charReplace(self, charArray, target):
        for char in charArray:
            if char in target:
                target = target.replace(char, '')
        return target

    def setProvisioning(self):
        keys = self.parseNames()
        if not keys:
            return False
        data = {}
        for index, key in keys.items():
            if self[key]:
                #Only pull values we do have
                data[index] = self[key]
        resp = self.session.post(f'https://{self.ip}/form-submit', auth=self.basicAuth, cookies=self.session.cookies, verify=False, data=data)
        if "CONF_CHANGE" in resp.text:
            return True
        else:
            return False