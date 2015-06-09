##############################################################################################################################
#                               			OFFENSIVE FORENSIC FRAMEWORK      					                            			   			 #
#											            (WIRELESS NETWORK FORENSICS MODULE)       			                                           #
#														                  (JUNE 2015)			   			                                                       #
#                   															 BY   	   			                                                           #
#						                           KEELYN ROBERTS(slacker007) 					   			 				                                 #
##############################################################################################################################


######################################### Function & Variable Formatting Guide ###############################################
# Global Variables are all uppercase EX: GLOBAL_VARIABLE = 0
# local Variables are in all lowercase EX: local_variable = 0
# Function Names are written by capitalizing the first letter of each word EX: def FunctionName(): or def Function_Name():


import _winreg
import xml.etree.ElementTree as DATA_HANDLER
from xml.dom import minidom


#***********************************************************************************
# Global Variables
#***********************************************************************************

ROOT = DATA_HANDLER.Element("Root")

########################	Static Registry Keys	################################
NETCARD_GUID = r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards'
CURRENT_NET_TCPIP_INFO = r'SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces'
NETWORK_HISTORY = r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles'
GATEWAY_MAC_HISTORY = r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged'

def Read_Subkeys (key): #(FUNCTION THAT READS OPENED HIVE KEY DATA INTO A //GENERATOR OBJECT//  TO REDUCE MEMORY FOOTPRINT!)
	counter = 0
	while True:
		try:
			subkey = _winreg.EnumKey(key, counter)
			yield subkey
			counter += 1
		except WindowsError as e:
			break
		
def Read_Key_Values (key): #(FUNCTION THAT READS THE VALUES OF AN OPENED SUBKEY USING A //GENERATOR OBJECT// TO REDUCE MEMORY FOOTPRINT!)
	counter = 0
	while True:
		try:
			keyvalue = _winreg.EnumValue(key, counter)
			yield keyvalue
			counter += 1
		except WindowsError as e:
			break

def Iterate_Reg_Keys(hkey, key_path, tabs=0): #(FUNCTION THAT CONTROLS THE ITERATION THROUGH SUBKEY & VALUES)
	new_tag = DATA_HANDLER.SubElement(ROOT, "New_Key")
	key = _winreg.OpenKey(hkey, key_path, 0, _winreg.KEY_READ)
	for subkey_name in Read_Subkeys(key): #(LOOP THROUGH THE REGISTRY KEY AND OPEN EACH SUBKEY)
		subkey_path = "%s\\%s" % (key_path, subkey_name)
		Iterate_Reg_Keys(hkey, subkey_path, tabs+1)
		subkey_value_path = _winreg.OpenKey(hkey, subkey_path, 0, _winreg.KEY_READ)
		data_found = False
		for subkey_value in Read_Key_Values(subkey_value_path): #(LOOP THROUGTH THE SUBKEY TO PULL VALUES FROM SUBKEY)
			data_found = True
			if isinstance(subkey_value[1], str):
				converted_from_ascii = ":".join("{:02x}".format(ord(c)) for c in subkey_value[1])
				value_data1 = str(subkey_value[0])
				value_data2 = str(converted_from_ascii)
				DATA = DATA_HANDLER.SubElement(new_tag, "DATA_SET")
				DATA_HANDLER.SubElement(DATA, value_data1, id = value_data1).text = value_data2
				DATA = subkey_name
			if not isinstance(subkey_value[1],str):
				value_data1 = str(subkey_value[0])
				value_data2 = str(subkey_value[1])
				DATA = DATA_HANDLER.SubElement(new_tag, "DATA_SET")
				DATA_HANDLER.SubElement(DATA, value_data1, id = value_data1).text = value_data2
				DATA = subkey_name
		if data_found == False:
			
			DATA = DATA_HANDLER.SubElement(new_tag, "DATA_SET")
			DATA_HANDLER.SubElement(DATA, "NO VALUES FOUND")
			
	_winreg.CloseKey(key)
	   
def Data_Writer():

	ALL_DATA = DATA_HANDLER.ElementTree(ROOT)
	ALL_DATA.write("netdata.xml")
	print "Done Writing File............."
		
	return

# EXECUTION.........................................
Iterate_Reg_Keys(_winreg.HKEY_LOCAL_MACHINE, NETCARD_GUID)
Iterate_Reg_Keys(_winreg.HKEY_LOCAL_MACHINE, CURRENT_NET_TCPIP_INFO)
Iterate_Reg_Keys(_winreg.HKEY_LOCAL_MACHINE, NETWORK_HISTORY)
Iterate_Reg_Keys(_winreg.HKEY_LOCAL_MACHINE, GATEWAY_MAC_HISTORY)
Data_Writer()




