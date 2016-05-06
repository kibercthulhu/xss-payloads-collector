__author__ = "stmerry"

from lxml import html
import requests
import urlparse
import urllib
import argparse
import getpass
from Pastebin import PastebinAPI
from time import sleep
import datetime

DOMAIN = "https://www.openbugbounty.org"

def get_incidents(page):
    """
        Get last 60 full exposure incident page links
        Requires page = page/1/ or page/2/, etc.
    """
    try:
        # possible to loop through /page/1/, /page/2/, etc. to get even more results
        page = requests.get(DOMAIN + "/incidents/" + page)
        tree = html.fromstring(page.content)
        links = tree.xpath("//div[@class='cell1']/a/@href")

        for pos, item in enumerate(links):
            item = DOMAIN + item
            links[pos] = item
            
        return links
    except:
        return "Error getting page content..."

def get_exposure(incident):
    """
        Get exposed link (incl. XSS payload) from incident page
    """
    # get incident vulnerable URL
    # this also checks if GET or POST payload
    try:
        page = requests.get(incident)
        tree = html.fromstring(page.content)
        xss_link = tree.xpath("//p[@class='urltxt']/text()")
    except:
        return "Error getting page content..."

    try:
        if len(xss_link) > 1:
            # POST payload
            # + remove hostname
            post_data = tree.xpath("//textarea[@name='post']/text()")
            for item in post_data:
                return item
        else:
            # GET payload
            # + remove hostname
            vuln_url = tree.xpath("//td[@class='url']/a/@href")
            for item in vuln_url:
                return item
    except:
        return "Error getting payload..."
    
def strip_hostname(raw):
    """
        Strip hostname from url and unquote characters
    """
    try:
        hostname = urlparse.urlparse(raw).hostname
        item = urllib.unquote(raw.split(hostname, 1)[-1])
        return item
    except:
        pass

def pb_generate_user_key(pb_devkey, pb_user, pb_pw):
    """
        Generate Pastebin session key for user
    """
    try:
        x = PastebinAPI()
        pb_sessionkey = x.generate_user_key(pb_devkey, pb_user, pb_pw)
        return pb_sessionkey
    except:
        return "Error getting Pastebin session key... check your deets"

def pb_submit_paste(pb_devkey, content, pastename, pb_sessionkey, cat):
    """
        Submit the paste to Pastebin
    """
    x = PastebinAPI()
    url = x.paste(pb_devkey, content, paste_name = pastename, api_user_key = pb_sessionkey, paste_private = cat)
    return url

def cleanup(raw):
    raw = [x for x in raw if x is not None]
    uniq = []
    [uniq.append(i) for i in raw if not uniq.count(i)]
    return uniq
                    
def main(pb_user, pb_devkey):
    """
        Gather payloads every X hours and generate associated Pastebin links
        Ex: add while True loop + sleep(86400) for 24 hours
    """
    # get user Pastebin password
    # + generate session key
    pb_pw = getpass.getpass("Enter Pastebin password for user " + pb_user + ":\n")
    print "Thanks! *Nom nom nom*\n"
    print "[*] Generating Pastebin session key..."
    pb_sessionkey = pb_generate_user_key(pb_devkey, pb_user, pb_pw)

    # create list with payloads (actually URLs incl. payloads)
    # find a way to extract XSS payloads only?!
    print "[*] Getting exposures..."
    raw = []

    for i in range(1, 1870):
        page = "page/" + str(i) + "/"
        print "\t[*] Page " + str(i) + " of 1869"
        for link in get_incidents(page):
            raw.append(get_exposure(link))

        # strip hostnames
        print "[*] Stripping hostnames..."
        for pos, item in enumerate(raw):
            item = strip_hostname(item)
            raw[pos] = item

        # clean up list
        print "[*] Cleaning up..."
        uniq = cleanup(raw)        
        
        # create paste
        print "[*] Creating paste...\n"
        pastename = "XSS Payloads [" + datetime.datetime.now().strftime("%d/%m/%Y | %H:%M:%S") + "]"
        print "[*] Paste created @ " + pb_submit_paste(pb_devkey, uniq, pastename, pb_sessionkey, "unlisted")

        # empty raw list
        del raw[:]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-u", "--username",
                        default=None,
                        required=True,
                        help="Pastebin username")
    parser.add_argument("-k", "--key",
                        default=None,
                        required=True,
                        help="Pastebin API dev key")

    main(parser.parse_args().username, parser.parse_args().key)
