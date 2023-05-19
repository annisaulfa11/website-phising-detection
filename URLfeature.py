from urllib.parse import urlparse,urlencode
import ipaddress
import re

from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime

from lxml import etree

import requests

import numpy as np

# Returns the domain of the url
def Domain(url):
    urlData = urlparse(url)
    urlLocation=urlData.netloc
    if re.match(r"^www.",urlLocation):
        domain = urlLocation.replace("www.","")
        return domain
    else:
        return 'NotFound'

# Checks whether the url contains ip address
def ipURL(url):
    try:
        ipaddress.ip_address(url)
        isIP = 1
    except:
        isIP = 0
    return isIP

# Does the url contain @ symbol
def haveAtSymbol(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

# Length of url
def Length(url):
    if len(url) < 55:
        length = 0
    else:
        length = 1
    return length

# No. of Subpages in url
def pathDepth(url):
    urlData = urlparse(url)
    urlPath = urlData.path
    depth = urlPath.count('/')
    return depth

# Redirection present in url
def redirectPresent(url):
    pos = url.rfind('//')
    if pos > 7:
        return 1
    else:
        return 0

# Scheme of url
def Scheme(url):
    urlData = urlparse(url)
    urlScheme = urlData.scheme
    if (urlScheme == 'https'):
        return 1
    else:
        return 0

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# Whether a url is a shortened URL
def urlShortening(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# Presence of '-' in url
# generally sites dont use '-' to seperate the words of site
def presenceOfDash(url):
    urlLocation = urlparse(url).netloc
    if '-' in urlLocation:
        return 1
    else:
        return 0

# Get Domain DNS related details using whois server
def domainDataExtract(url):
    url = urlparse(url).netloc
    dictURL={}
    html = BeautifulSoup(urllib.request.urlopen("https://www.whois.com/whois/" + url).read())
    domain_data_label = html.find_all(attrs={'class':'df-label'})
    
    if(len(domain_data_label)<5): return {}
    
    domain_data_value = html.find_all(attrs={'class':'df-value'})
    for i in range(5):
        domain_data_label[i]=domain_data_label[i].get_text().replace(':', '')
        domain_data_value[i]=domain_data_value[i].get_text().replace(':', '')
        
    for key in domain_data_label[:5]:
        for value in domain_data_value[:5]:
            dictURL[key] = value
            domain_data_value.remove(value)
            break
    return dictURL

# Rank by traffic on Alexa database
def rankByTraffic(url):
    try:
        url = urllib.parse.quote(url)
        alexaDB = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml")
        rank = int(alexaDB.find("REACH")['RANK'])
    except TypeError:
        return 1
    if rank<100000:
        return 0
    else:
        return 1

# Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domainData):
    creation_date = domainData['Registered On']
    expiration_date = domainData['Expires On']
    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
        try:
            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain/30) < 6):
            age = 1
        else:
            age = 0
        return age

# End time of domain: The difference between termination time and current time (Domain_End) 
def domainEnd(domainData):
    expiration_date = domainData['Expires On']
    if isinstance(expiration_date,str):
        try:
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end/30) < 6):
            end = 0
        else:
            end = 1
        return end

# IFrame Redirection
def iframeRedirection(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

# Effects of mouse over on status bar
def StatusBarModification(response): 
    if response == "" :
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

# Checks whether right click is enabled or disabled
def rightClickEnable_Disable(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

# The number of forwardings a page goes through
def forwardHistory(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1

#Function to extract features
def featureAppending(url):
    features = []
    test_domain = Domain(url)
    #Address bar based features
    features.append(ipURL(url))
    features.append(haveAtSymbol(url))
    features.append(Length(url))
    features.append(pathDepth(url))
    features.append(redirectPresent(url))
    features.append(Scheme(url))
    features.append(urlShortening(url))
    features.append(presenceOfDash(url))
    
    #DNS based features
    dns = 0
    domainData={}
    try:
        domainData = domainDataExtract(url)
        if(domainData=={}):
            dns=1
    except:
        dns = 1
    features.append(dns)
    features.append(rankByTraffic(url))
    features.append(1 if dns == 1 else domainAge(domainData))
    features.append(1 if dns == 1 else domainEnd(domainData))
    
    #Javascript based features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframeRedirection(response))
    features.append(StatusBarModification(response))
    features.append(rightClickEnable_Disable(response))
    features.append(forwardHistory(response))
    
    
    return features

def decetion(url):
    computed = featureAppending(url)
    return np.array([computed])