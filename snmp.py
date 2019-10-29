from pysnmp.hlapi import *
import nmap

def SNMP_V2MIB_GET(HOST, COMMUNITY, VAR, INSTANCE):

    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity('SNMPv2-MIB', VAR, INSTANCE)))

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                return [x.prettyPrint() for x in varBind]

def SNMP_OID_GET(HOST, COMMUNITY, OID):


    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(OID)),lookupMib=False)

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                return [x.prettyPrint() for x in varBind]




class SNMP_OBJECT:
    def __init__(self,HOST,COMMUNITY):
        self.HOST=HOST
        self.COMMUNITY=COMMUNITY
        self.sysDescr=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysDescr',0)
        self.sysObjectID=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysObjectID',0)
        self.sysUpTime=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysUpTime',0)
        self.sysName=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysName',0)
        self.IfNumber=(SNMP_OID_GET(self.HOST,self.COMMUNITY,'.1.3.6.1.2.1.2.1.0')[1]) #number of interfaces, includes management interface, and SVI's, etc...

    def GET_DESC(self):
        return self.sysDescr[1]
    def GET_ID(self):
        return self.sysObjectID[1]
    def GET_UPTIME(self):
        n = int(self.sysUpTime[1])/100
        day=n//(24*3600)

        n = n % (24 * 3600)
        hour = n//3600
        n %= 3600
        minutes = n//60
        n %=60
        seconds = n
        uptime = "Days: " + " " + str(day) + " ,  Hours : " + str(hour) + " ,  Minutes : " + str(minutes) + " ,  Seconds : " + str(seconds)

        return uptime
    def GET_NAME(self):
        return self.sysName[1]
    def GET_IFNUM(self):
        return self.IfNumber

class NET_DISC:
    def __init__(self,NET,MASK):
        self.NETWORK=NET
        self.NETMASK=MASK
        self.nm = nmap.PortScanner()
    def DISCOVER(self):
        nNET=self.NETWORK + "/" + self.NETMASK
        self.nm.scan(hosts=nNET, arguments='-sU -p 161')
    def GET_NET(self):
        return self.nm.csv()






#SWITCH1=SNMP_OBJECT('192.168.127.52','public')
#print('NAME' + " " + SWITCH1.GET_NAME())
#print('sys desc' + " " + SWITCH1.GET_DESC())
#print('ID' + " " + SWITCH1.GET_ID())
#print('UPTIME' + " " + SWITCH1.GET_UPTIME())
#print('Number of Interfaces: ' + SWITCH1.GET_IFNUM())

network=NET_DISC('192.168.127.0','24')
network.DISCOVER()
print(network.GET_NET())

