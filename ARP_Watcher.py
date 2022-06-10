#!/usr/bin/env python
#-*- coding: utf-8 -*-

import json
import sys,os
import codecs
import socket
import requests
import datetime
import time
import random
import scapy.all as scapy

import urllib.parse

import log

try:
	from termcolor import colored
except Exception as inst:
	# Ok we can run without color, but world look less fun in the black matrix
	print(u"run pip install termcolor to get some color there...")
	def colored(txt,color):
		return txt
	def cprint(txt,color,on_color):
		print(txt)


Scan_Port=[
		7,		# Echo Protocol
		20,		# FTP data
		21,		# FTP Control
		22,		# SSH
		23,		# Telnet
		25,		# SMTP
		53,		# DNS
		67,		# DHCP
		68,		# DHCP
		69,		# TFTP
		80,		# HTTP
		110,	# POP 3
		115,	# SFTP
		119,	# NNTP
		123,	# NTP
		137,	# NetBios NS
		138,	# Netbios DS
		139,	# NetBios SS
		143,	# IMAP
		161,	# SNMP
		162,	# SNMP Trap
		194,	# IRC
		220,	# IMAP v3
		443,	# HTTPS
		445,	# Miscrosoft DS AD Share SMB
		465,	# SMTP Ssl
		514,	# Syslog
		853,	# DNS Ssl
		992,	# Telnet Ssl
		993,	# IMAP Ssl
		994,	# IRC Ssl
		995,	# POP3 Ssl
		1025,	# NFS
		1194,	# OPEN VPN
		1293,	# IP Sec
		1433,	# MS SQL Server
		3306,	# MySQL
		5432,	# PostGreSQL
		8080,	#
		8443	#
		]

def List_MyIPs():
    return socket.gethostbyname_ex(socket.gethostname())[2]

def Get_MAC(network, IP_as_key = False, NIC_Info={}, timeout = 2, verbose = 0):
    if verbose>0: print("Working on: "+str(network))
    ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=str(network)), timeout=timeout,verbose=verbose)
    # print(ans)
    Mac_List={}
    for element in ans:
        One_Element={}
        One_Element["IPv4"] = str(element[1].psrc).upper()
        One_Element["Mac"]  = str(element[1].hwsrc).upper()
        #Trying to get DNS name
        One_Element["DNS"] = "Unknown"
        try:
            One_Element["DNS"] = str(socket.gethostbyaddr(One_Element["IPv4"])[0])
        except Exception as inst:
            if verbose>1: print("Retreiving Hostanme Err: "+str(inst))
            One_Element["DNS"] = "UnRetreivable"
        #Do we know the NIC manufacturer
        One_Element["NIC"]=""
        identifier = str(One_Element["Mac"].replace(":","").replace("-","")).upper()[0:6]
        if identifier in NIC_Info.keys(): One_Element["NIC"] = NIC_Info[identifier]



        if verbose>0: print(One_Element["IPv4"].rjust(15)+" - " + One_Element["Mac"] + " - " + str(One_Element["DNS"]))
        if IP_as_key:
            Mac_List[One_Element["IPv4"]]=One_Element
        else:
            Mac_List[One_Element["Mac"]]=One_Element

    if verbose>0: print("We get "+str(len(Mac_List))+" elements on "+str(network))
    return Mac_List

def Not_in_First(First_Dict,SecondDict,invert=False):
    result = {}
    for one_key in SecondDict.keys():
        if one_key in First_Dict.keys():
            if invert: result[one_key]= SecondDict[one_key]
        else:
            if not invert: result[one_key]= SecondDict[one_key]
    return result

def ARPWatch(parameters):
    Fic_Whitelist       =parameters["Conf"]["WhiteList_ARP_File"]
    Fic_LastARP         =parameters["Conf"]["Last_ARP_File"]
    Fic_NIC             =parameters["Conf"]["NIC_Manufacturer_File"]
    Grace_File          =parameters["Conf"]["Grace_File"]
    Log_ARP             =parameters["Conf"]["Log_ARP"]
    Scan_Report         =parameters["Conf"]["Scan_Report"]
    Log_Folder          =parameters["Conf"]["Log_Fold"]
    verbose             =parameters["Conf"]["Log_Level"]

    if os.path.isdir(parameters['Conf']['Log_Fold']):
        print("Log Creation")
        mylog=log.ClassicalLogger(parameters['Conf']['Log_Fold'],'ARP_Watcher',verbose)
    else:
        print("Log Creation Loc")
        mylog=log.ClassicalLogger('.','Ecex_ARP_Watcher',verbose)

    mylog.info("Starting")

    if verbose>2:
        print("-"*70)
        print("ARP Watcher (parameters".center(70))
        print("-"*70)
        print("Fic_Whitelist".ljust(20)+" : "+str(Fic_Whitelist))
        print("Fic_LastARP".ljust(20)+" : "+str(Fic_LastARP))
        print("Fic_NIC".ljust(20)+" : "+str(Fic_NIC))
        print("Grace_File".ljust(20)+" : "+str(Grace_File))
        print("Log_ARP".ljust(20)+" : "+str(Log_ARP))
        print("Scan_Report".ljust(20)+" : "+str(Scan_Report))
        print("Log_Folder".ljust(20)+" : "+str(Log_Folder))
        print("verbose".ljust(20)+" : "+str(verbose))
        print("-"*70)

    #Load NIC_Manufacturer
    if verbose>1:
        print("Loading NIC_Manufacturer")
        print("-"*70)
    if os.path.exists( Fic_NIC):
        NIC_Manufacturer = json.load(codecs.open(Fic_NIC,'r','utf-8'))
    else:
        NIC_Manufacturer = {}

    #Load Whitelist
    if verbose>1:
        print("Loading Fic_Whitelist")
        print("-"*70)
    if os.path.exists(Fic_Whitelist):
        Whitelist = json.load(codecs.open(Fic_Whitelist,'r','utf-8'))
    else:
        Whitelist = {}
    
    #Load Last ARP Table
    if verbose>1:
        print("Loading Fic_LastARP")
        print("-"*70)
    if os.path.exists(Fic_LastARP):
        LastARP = json.load(codecs.open(Fic_LastARP,'r','utf-8'))
    else:
        LastARP = {}
    
    #Get Actual ARP Table
    if verbose>1:
        print("ARP Ping all")
        print("-"*70)
    ARP_Now=Get_MAC(network="192.168.1.0/24",NIC_Info=NIC_Manufacturer,verbose=verbose)

    if verbose>1:
        print("-"*70)
        print("Last ARP")
        print(json.dumps(LastARP,indent=4))
        print("-"*70)
        print("ARP Now")
        print(json.dumps(ARP_Now,indent=4))
        print("-"*70)


    #Finding new Element
    New_Elements = Not_in_First(LastARP,ARP_Now)

    # Findig New and New Not whitelisted
    New_Elements_Not_Whitelisted = Not_in_First(Whitelist,New_Elements)
    
    # Finding Disapeared
    Disapeared_Element = Not_in_First(ARP_Now,LastARP)

    # Whitelisted Connected
    Whitelisted_Connected = Not_in_First(Whitelist,ARP_Now,invert=True)
    
    # Whitelisted Newly Connected
    Whitelisted_Newly_Connected = Not_in_First(Whitelist,New_Elements,invert=True)

    #Saving New ARP
    if verbose>1:
        print("Writing New ARP")
        print("-"*70)
    fic = codecs.open(Fic_LastARP,"w","utf-8")
    fic.write(json.dumps(ARP_Now,indent=4))
    fic.close()
    
    sms_message = "ARP Watch: "
    
    #If we can, send a syslog
    Syslog_Server = None
    if "syslog" in parameters.keys():
        try:
            Syslog_Server=parameters["syslog"]["server"]
            Syslog_facility=parameters["syslog"]["facility"]
            Syslog_priority=parameters["syslog"]["prio_kno"]
            Syslog_isUDP=(parameters["syslog"]["Protocol"].upper() == "UDP")
        except Exception as inst:
            # Probably a parameter probleme
            Syslog_Server = None


    # Detect new Element not Whitelisted
    if verbose>1:
        print("Detect new Element not Whitelisted ("+str(len(New_Elements_Not_Whitelisted))+" elements)")
        print("-"*70)
    for one_new in New_Elements_Not_Whitelisted.keys():
        one_new_nw = New_Elements_Not_Whitelisted[one_new]
        message = "Unknown Co "+one_new_nw["IPv4"].replace("192.168.1","")+" mac " + one_new_nw["Mac"]
        if not one_new_nw["DNS"] in ['Unknown','UnRetreivable']:
            message += " named " + str(one_new_nw["DNS"])
        
        ScanRes=None
        if len(Scan_Port)>0:
            #Let's Scan this new unknown
            ScanRes = Scan_an_IP(IP=one_new_nw["IPv4"],Ports=Scan_Port,verbose=verbose)
            if len(Scan_Report)>1:
                ScanFile = Scan_Report.replace("<MAC_ADDR>",one_new_nw["Mac"].replace(":","-"))
                #If exist load
                AllScan=[]
                if os.path.exists(ScanFile):
                    AllScan = json.load(codecs.open(ScanFile,"r","utf-8"))
                AllScan.append(ScanRes)
                # Write all scan (or only one)
                fic = codecs.open(ScanFile,"w","utf-8")
                fic.write(json.dumps(AllScan,indent=4))
                fic.close()
            if len(ScanRes["Opened"])>0: message += " with "+ ",".join(ScanRes["Opened"])
        
        #Log this to file, if provided
        if os.path.exists(Log_ARP):
            fic = codecs.open(Log_ARP,"w","utf-8")
            fic.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%s;")+message+"\r\n")
            fic.close()
        
        #If we can, send a syslog
        if not Syslog_Server is None:
            SyslogMessage="src_ip="+str(one_new_nw["IPv4"])+",srcmac="+str(one_new_nw["Mac"])+",dns="+str(one_new_nw["DNS"])+",status=Connected"
            if not ScanRes is None:
                if "Opened" in ScanRes.keys():
                    SyslogMessage+=",ports="+"-".join(ScanRes["Opened"])
            SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
            del SyslogMessage
        
        #If we can, send a sms
        if "Free_SMS" in parameters.keys():
            if verbose>1: print("\t "+str(one_new)+": Connection Unknown Alert SMS")
            sms_message += message + " "
        print(colored(message,"red"))
        del message

    # Detect Disapeared (Log unknown, alert Whitelisted)
    if verbose>1:
        print("Detect Disapeared ("+str(len(Disapeared_Element))+" elements)")
        print("-"*70)
    for one_del in Disapeared_Element.keys():
        one_del_dict = Disapeared_Element[one_del]
        # print("---------------------------")
        # print(colored(one_del_dict,"red")) 
        # print("---------------------------")
        if one_del in Whitelist.keys():
            message = "Whitelisted Leave "+one_del_dict["IPv4"].replace("192.168.1","")+" mac " + one_del_dict["Mac"]
            if not one_del_dict["DNS"] in ['Unknown','UnRetreivable']:
                message += " named " + str(one_del_dict["DNS"])
            
            #Log this to file, if provided
            if os.path.exists(Log_ARP):
                fic = codecs.open(Log_ARP,"w","utf-8")
                fic.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%s;")+message+"\r\n")
                fic.close()
            
            #If we can, send a syslog
            if not Syslog_Server is None:
                SyslogMessage="src_ip="+str(one_del_dict["IPv4"])+",srcmac="+str(one_del_dict["Mac"])+",dns="+str(one_del_dict["DNS"])+",status=Disconnected"
                SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
                del SyslogMessage
            
            # Alert (if needed)
            print("Options = "+str(Whitelist[one_del]["Options"]))
            if 'NoDiscoAlert' in Whitelist[one_del]["Options"]:
                if verbose>1: print("\t "+str(one_del)+": No Disconnection Whitelisted Alert")
            else:
                if GraceCount(one_del,Grace_File)>Whitelist[one_del]["Grace_Count"]:
                    #If we can, send a sms
                    if verbose>1: print("\t "+str(one_del)+": Disconnection Whitelisted Alert SMS")
                    if "Free_SMS" in parameters.keys():
                        if verbose>1: print("\t "+str(one_del)+": Disconnection Whitelisted Alert SMS")
                        sms_message += message.replace("ARP Watch: ","") + " "
                else:
                    if verbose>1: print("\t "+str(one_del)+": Disconnection Whitelisted Alert SMS (still in Gracetime)")
            
            print(colored(message,"cyan"))
        else:
            message = "Unknown Leave "+one_del_dict["IPv4"].replace("192.168.1","")+" mac " + one_del_dict["Mac"]
            if not one_del_dict["DNS"] in ['Unknown','UnRetreivable']:
                message += " named " + str(one_del_dict["DNS"])
            
            #Log this to file, if provided
            if os.path.exists(Log_ARP):
                fic = codecs.open(Log_ARP,"w","utf-8")
                fic.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%s;")+message+"\r\n")
                fic.close()
            
            #If we can, send a syslog
            if not Syslog_Server is None:
                SyslogMessage="src_ip="+str(one_del_dict["IPv4"])+",srcmac="+str(one_del_dict["Mac"])+",dns="+str(one_del_dict["DNS"])+",status=Disconnected"
                if not ScanRes is None:
                    if "Opened" in ScanRes.keys():
                        SyslogMessage+=",ports="+"-".join(ScanRes["Opened"])
                SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
                del SyslogMessage
                
            #If we can, send a sms
            if verbose>1: print("\t "+str(one_del)+": Disconnection Unknown Alert SMS")
            if "Free_SMS" in parameters.keys():
                if verbose>1: print("\t "+str(one_del)+": Disconnection Unknown Alert SMS")
                sms_message += message.replace("ARP Watch: ","") + " "
            
            print(colored(message,"magenta"))
        del message

    # Log Whitelisted Connected
    if verbose>1:
        print("Log Whitelisted Connected ("+str(len(Whitelisted_Newly_Connected))+" elements)")
        print("-"*70)
    for one_new_wl in Whitelisted_Newly_Connected.keys():
        one_new_wl_dict = Whitelisted_Newly_Connected[one_new_wl]
        message = "Whitelisted Connected "+one_new_wl_dict["IPv4"].replace("192.168.1","")+" mac " + one_new_wl_dict["Mac"]
        if not one_new_wl_dict["DNS"] in ['Unknown','UnRetreivable']:
            message += " named " + str(one_new_wl_dict["DNS"])

        #Log this to file, if provided
        if os.path.exists(Log_ARP):
            fic = codecs.open(Log_ARP,"w","utf-8")
            fic.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%s;")+message+"\r\n")
            fic.close()
        
        #If we can, send a syslog
        if not Syslog_Server is None:
            SyslogMessage="src_ip="+str(one_new_wl_dict["IPv4"])+",srcmac="+str(one_new_wl_dict["Mac"])+",dns="+str(one_new_wl_dict["DNS"])+",status=Disconnected"
            SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
            del SyslogMessage

        # Alert (if needed)
        print("Options = "+str(Whitelist[one_new_wl]["Options"]))
        if 'NoCoAlert' in Whitelist[one_new_wl]["Options"]:
            if verbose>1: print("\t "+str(one_new_wl)+": No Connection Alert")
        else:
            #If we can, send a sms
            if "Free_SMS" in parameters.keys():
                if verbose>1: print("\t "+str(one_new_wl)+": WL Connection Alert SMS")
                sms_message += message.replace("ARP Watch: ","") + " "
        
        print(colored(message,"green"))

    # Whitelisted Port Check
    if verbose>1:
        print("Log Whitelisted Port Check ("+str(len(Whitelist))+" elements)")
        print("-"*70)
    for one_wl in Whitelist.keys():
        one_wl_dict = Whitelist[one_wl]
        if len(one_wl_dict["Check"])<1: continue
        
        if one_wl in Whitelisted_Connected.keys():
            if verbose>1:
                print(colored("\tTesting "+str(one_wl_dict["IPv4"]),"blue"))
            #Check Port
            for one_port in one_wl_dict["Check"]:
                if Check_Port_IP(one_wl_dict["IPv4"], Port=one_port, timeout=0.5, verbose=0):
                    #If we can, send a syslog
                    if verbose>1: print(colored("\t\t + Port :"+str(one_port)+" : Responding","blue"))
                    if not Syslog_Server is None:
                        SyslogMessage="src_ip="+str(one_wl_dict["IPv4"])+",srcmac="+str(one_wl_dict["Mac"])+",dns="+str(one_wl_dict["DNS"])+",status=Open,port="+str(one_port)
                        SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
                        del SyslogMessage
                else:
                    #If we can, send a syslog
                    if verbose>1: print(colored("\t\t + Port :"+str(one_port)+" : Closed","blue"))
                    if not Syslog_Server is None:
                        SyslogMessage="src_ip="+str(one_wl_dict["IPv4"])+",srcmac="+str(one_wl_dict["Mac"])+",dns="+str(one_wl_dict["DNS"])+",status=Closed,port="+str(one_port)
                        SyslogSend(Syslog_Server,SyslogMessage,Syslog_facility,Syslog_priority,Syslog_isUDP,verbose)
                        del SyslogMessage
                    #If we can, send a sms
                    if "Free_SMS" in parameters.keys():
                        if verbose>1: print("\t "+str(one_wl_dict)+": Port Down SMS")
                        message = "Whitelisted Port Down "+one_wl_dict["IPv4"].replace("192.168.1","")+" port: "+str(one_port)+" mac " + one_wl_dict["Mac"]
                        sms_message += message.replace("ARP Watch: ","") + " "
        else:
            if verbose>1:
                print(colored("\tNo testing not connected "+str(one_wl_dict["IPv4"])+" ("+str(one_wl_dict["Mac"])+")","blue"))
                # print(Whitelisted_Connected)
            #Alert port check not connected
            pass

    # Deleting Whitelisted in Grace.json
    if verbose>1:
        print("Delete from Grace List Whitelisted ("+str(len(Whitelist))+" elements)")
        print("-"*70)

    if os.path.exists(Grace_File):
        GraceList = json.load(codecs.open(Grace_File,'r','utf-8'))
        # print(GraceList)
        for one_wl in Whitelist.keys():
            if one_wl in Whitelisted_Connected:
                if one_wl in GraceList.keys():
                    if verbose>1:
                        print("\t Deleting "+str(one_wl))
                    GraceList.pop(one_wl,None)
        
        fic = codecs.open(Grace_File,"w","utf-8")
        fic.write(json.dumps(GraceList,indent=4))
        fic.close()

    #SMS Sending
    if verbose>1 and len(sms_message)>15:
        print("Sending SMS")
        print("-"*70)

    if len(sms_message)>15:
        mylog.info("Alert SMS Needed")
        SMS_Send(sms_message,parameters)

    mylog.info("Finished")

def Check_Port_IP(
        IP,
        Port=Scan_Port,
        timeout=0.5,
        verbose=0):
    if type(Scan_Port) is str:
		#Well it's not a classical TCP check
        try:
            if Scan_Port.startswith("HTTP_"):
                response = requests.get("http://"+str(IP))

                if Scan_Port == "HTTP_"+str(response.status_code): return True
            elif Scan_Port.startswith("HTTPS_"):
                response = requests.get("https://"+str(IP))
                if Scan_Port == "HTTPS_"+str(response.status_code): return True
        
        except Exception as inst:
            # one[1].show()
            pass
        return False

    elif type(Scan_Port) is int:
        ans, unans = scapy.sr(scapy.IP(dst=IP)/scapy.TCP(dport=Port,sport=random.randrange(50000, 65535),flags="S")/"GET / HTTP/1.0\r\n\r\n", timeout=timeout,verbose=verbose)
        for one in ans: 
            try:
                if one[1][scapy.TCP].flags=="SA":
                    return True
                else:
                    return False
            except Exception as inst:
                # one[1].show()
                pass
    
    return False

def Scan_an_IP(
        IP,
        Ports=Scan_Port,
        timeout=0.5,
        verbose=0):
    ans, unans = scapy.sr(scapy.IP(dst=IP)/scapy.TCP(dport=Ports,sport= random.randrange(50000, 65535),flags="S")/"GET / HTTP/1.0\r\n\r\n", timeout=timeout,verbose=verbose)
    ScanRes={}
    ScanRes["IP"]=IP
    ScanRes["Date"]=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%s;")
    ScanRes["Opened"]=[]
    ScanRes["TCP"]={}
    for one in ans: 
        try:
            if one[1][scapy.TCP].flags=="SA":
                ScanRes["TCP"][one[1][scapy.TCP].sport]=Get_Banner(IP,one[1][scapy.TCP].sport)
                ScanRes["Opened"].append("TCP "+str(one[1][scapy.TCP].sport))
                # print("Open "+str(one[1][scapy.TCP].sport))
            else:
                ScanRes["TCP"][one[1][scapy.TCP].sport]="Reset ("+str(one[1][scapy.TCP].flags)+")"
                # print("Reset "+str(one[1][scapy.TCP].sport)+" "+str(one[1][scapy.TCP].flags))
        except Exception as inst:
            # one[1].show()
            pass
    
    for one in unans: 
        ScanRes["TCP"][one[0][scapy.TCP].dport]="Closed"
    
    return ScanRes

def Get_Banner(remoteServerIP,port,verbose=0):
		try:
			sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock2.connect((remoteServerIP,port))
			sock2.send(str.encode("Hello"))
			banner = sock2.recv(100).decode('utf-8').replace("\r\n"," - " ).replace("\r"," - " ).replace("\n"," - " )
			if banner[-3:]==" - ":banner=banner[:-3]
			sock2.close()
				
			return banner
		except Exception as inst:
			return u"No banner"
	
def SyslogSend(Server, Message, facility=16,priority=6,UDP=False,verbose=0):
    facilities= {
        0:"KERN",
        1:"USER",
        2:"MAIL",
        3:"DAEMON",
        4:"AUTH",
        5:"SYSLOG",
        6:"LPR",
        7:"NEWS",
        8:"UUCP",
        9:"CRON",
        10:"AUTHPRIV",
        11:"FTP",
        16:"LOCAL0",
        17:"LOCAL1",
        18:"LOCAL2",
        19:"LOCAL3",
        20:"LOCAL4",
        21:"LOCAL5",
        22:"LOCAL6",
        23:"LOCAL7"
    }
    priorities={
        0:"EMERG",
        1:"ALERT",
        2:"CRIT",
        3:"ERR",
        4:"WARNING",
        5:"NOTICE",
        6:"INFO",
        7:"DEBUG"}
    
    if not priority in priorities.keys(): raise Exception("Unknown Priority","Priority must be in "+str(priorities))
    if not facility in facilities.keys(): raise Exception("Unknown Facility","Facility must be in "+str(facilities))
    try:
        code = (priority << 3) | facility
        if UDP:
            syslog = scapy.IP(dst=Server)/scapy.UDP(dport=514)/scapy.Raw(load='<' + str(code) + '>' + time.strftime("%b %d %H:%M:%S ") + Message)
            scapy.send(syslog, verbose=0)
        else:
            syslog = scapy.IP(dst=Server)/scapy.TCP(dport=514)/scapy.Raw(load='<' + str(code) + '>' + time.strftime("%b %d %H:%M:%S ") + Message)
            scapy.sr(syslog, verbose=0)
    except Exception as inst:
        print("Syslog Error")
        print("-"*70)
        print(inst)
        pass

def SMS_Send(Message,Parameters):
    if len(Message)>15 and "Free_SMS" in Parameters.keys():
        try:
            sms_url = 'https://smsapi.free-mobile.fr/sendmsg?&user=<user>&pass=<password>&msg=<texte>'
            sms_url = sms_url.replace("<user>",     Parameters["Free_SMS"]["Login"])
            sms_url = sms_url.replace("<password>", Parameters["Free_SMS"]["Pass"])
            sms_url = sms_url.replace("<texte>",    urllib.parse.quote_plus(Message))
            requests.get(sms_url)
            del sms_url
        except Exception as inst:
            # Probably a parameter probleme
            pass

def GraceCount(MacAddr,GraceFile='.'+os.sep+'Grace.json'):
    if os.path.exists(GraceFile):
        GraceListe = json.load(codecs.open(GraceFile,'r','utf-8'))
    else:
        GraceListe = {}

    result = False
    
    if MacAddr in GraceListe.keys():
        GraceListe[MacAddr]+=1
    else:
        GraceListe[MacAddr]=1

    result = GraceListe[MacAddr]

    fic = codecs.open(GraceFile,"w","utf-8")
    fic.write(json.dumps(GraceListe,indent=4))
    fic.close()

    del fic

    return result

def main():
    Base_Folder="."
    params = json.load(open(Base_Folder+os.sep+'lang.json'))
    # print(json.dumps(params,indent=4))
    ARPWatch(params)

if __name__ == "__main__":
    main()
    # Scan_an_IP("192.168.1.254")
    # ARP_Now=Get_MAC(network="192.168.1.0/24",verbose=10)
    # print(ARP_Now)