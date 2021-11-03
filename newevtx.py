import os
import re
import csv
import mmap
from lxml import etree
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import xml.etree.ElementTree as ET

class fetch_src:
    def __init__(self):
        self.evtx_dict = {}
        self.line_fined = []
    
    def fetch_name(self): #Open EVTX-ATTACK_SAMPLES CSV File
        # Version
        #self.line_fined = ["Hashes"]
        self.line_fined = ["Provider Name", "Guid", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated SystemTime", "EventRecordID", "Execution ProcessID", "ThreadID", "Channel", "Computer", "Security UserID", "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentImage", "ParentCommandLine", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName", "State", "SchemaVersion", "ImageLoaded", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction", "SourceThreadId", "GrantedAcces", "CallTrace", "EventType", "TargetObject", "Details", "Hash", "Configuration", "ConfigurationFileHash", "PipeName", "Operation", "EventNamespace", "Name", "Query", "Type", "Destination", "Consumer", "Filter", "QueryName", "QueryStatus", "QueryResults", "IsExecutable", "Archived"]
        for i in range(0,len(self.line_fined)):
            self.evtx_dict[self.line_fined[i]] = None

with open('C:/Users/rocco/Downloads/EVTX-ATTACK-SAMPLES/babyshark_mimikatz_powershell.evtx', 'r') as log: #Open EVTX File
    fetch_column = fetch_src()
    fetch_column.fetch_name()
    with open('C:/Users/rocco/Downloads/EVTX-ATTACK-SAMPLES/parsed_evtx.csv','w+',newline='\n') as parsed_csv: #Open Parsed CSV File (Need to Create File)
        write_csv = csv.writer(parsed_csv, delimiter=',')
        write_csv.writerow(fetch_column.line_fined)
    
        buf = mmap.mmap(log.fileno(), 0, access=mmap.ACCESS_READ)
        fh = evtx.FileHeader(buf,0x00)
        for i in e_views.evtx_file_xml_view(fh):
            fined_xml = "<?xml version = \"1.0\" encoding = \"UTF-8\" ?>\n" + i[0]
            parsed_xml = ET.fromstring(fined_xml)
            
            #Parse System Values
            for j in range(0,len(parsed_xml[0])):
                if(len(parsed_xml[0][j].attrib) > 0):
                    for k in range(0,len(list(parsed_xml[0][j].attrib.keys()))):
                        attr_name = list(parsed_xml[0][j].attrib.keys())[k]
                        if (attr_name == 'Qualifiers'):
                            fetch_column.evtx_dict['EventID'] = parsed_xml[0][j].text
                        elif (parsed_xml[0][j].text != None):
                            fetch_column.evtx_dict[attr_name] = parsed_xml[0][j].text
                        elif (attr_name in list(fetch_column.evtx_dict.keys())):
                            fetch_column.evtx_dict[attr_name] = parsed_xml[0][j].attrib[attr_name]
                        else:
                            pass
                        
            
            #Parse EventData Values
            for j in range(0,len(parsed_xml[1])):
                if(len(parsed_xml[1][j].attrib) > 0):
                    if(parsed_xml[1][j].attrib["Name"] in list(fetch_column.evtx_dict.keys())):
                        fetch_column.evtx_dict[parsed_xml[1][j].attrib["Name"]] = parsed_xml[1][j].text

            #print(len(list(fetch_column.evtx_dict.values())))
            write_csv.writerow(list(fetch_column.evtx_dict.values())) #Write Parsed Data in Parsed CSV
            fetch_column.fetch_name()