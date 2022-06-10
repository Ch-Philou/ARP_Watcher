#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import sys
import codecs
import datetime
import json						# To load Parameters
import requests


url         = 'https://linuxnet.ca/ieee/oui/nmap-mac-prefixes'
Raw_file    = '/Scripts/ARP_Watcher/Elements/Raw_UOI.txt'
Final_JSON  = '/Scripts/ARP_Watcher/Elements/NIC_Manufacturer.json'

def main():
    #Step 1: retreive Liste from internet
    r = requests.get(url, allow_redirects=True)
    codecs.open(Raw_file, 'w','utf-8').write(r.text)

    #Step 2: read and create JSON
    OutputDict={}
    fic = codecs.open(Raw_file,'r')
    lines=fic.readlines()
    fic.close()

    for one_line in lines:
        Mac_Prefix=str(one_line.split("\t")[0]).upper()
        Vendor =str(one_line.split("\t")[1]).replace("\n","")

        OutputDict[Mac_Prefix]=Vendor

    fic = codecs.open(Final_JSON,'w', encoding='utf8')
    fic.write(json.dumps(OutputDict, sort_keys=True, indent=4))
    fic.close()
    del fic

if __name__ == '__main__':
	main()
	try:
		pass
	except Exception as inst:
		print("Something wrong:")
		print(str(inst))