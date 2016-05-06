# python
### get_payloads.py

Collects URLs submitted via full disclosure on OpenBugBounty.org. Hostnames are stripped to keep the XSS payloads. The longer term idea is to gather unique XSS payloads. PastebinAPI is used to create and submit a paste to Pastebin for each page of payloads gathered.
