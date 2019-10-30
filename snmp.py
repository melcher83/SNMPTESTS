#Jonathan Melcher
#jonathan@vlan404notfound.com
#
#

from pysnmp.hlapi import *
import nmap



def SNMP_V2MIB_GET(HOST, COMMUNITY, VAR, INSTANCE): #basic info gathering via SNMPv2-MIB

    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161),retries=3),
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
def SNMP_MIB_WALK(HOST, COMMUNITY,MIB, VAR):
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(COMMUNITY),
                              UdpTransportTarget((HOST, 161), retries=3),
                              ContextData(),
                              ObjectType(ObjectIdentity(MIB,VAR).addAsn1MibSource('MIBS','http://mibs.snmplabs.com/asn1/@mib@')),lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                print(' = '.join([x.prettyPrint() for x in varBind]))

def SNMP_MIB_GET(HOST, COMMUNITY,MIB, VAR, INSTANCE): #info gather via custom MIBS in MIBS folder or anything on the website mentioned.

    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161),retries=3),
                      ContextData(),
                      ObjectType(ObjectIdentity(MIB, VAR, INSTANCE).addAsn1MibSource('MIBS','http://mibs.snmplabs.com/asn1/@mib@')))

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                return [x.prettyPrint() for x in varBind]

def SNMP_OID_GET(HOST, COMMUNITY, OID): #more advanced gathering based on the OID


    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161),retries=3),
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




class SNMP_OBJECT: #Each device in network
    def __init__(self,HOST,COMMUNITY):
        self.HOST=HOST
        self.COMMUNITY=COMMUNITY
        self.sysDescr=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysDescr',0)
        self.sysObjectID=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysObjectID',0)
        self.sysUpTime=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysUpTime',0)
        self.sysName=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysName',0)
        if SNMP_MIB_GET(self.HOST,self.COMMUNITY,'IF-MIB','ifNumber',0) is not None:
            self.IfNumber=(SNMP_MIB_GET(self.HOST,self.COMMUNITY,'IF-MIB','ifNumber',0)[1]) #number of interfaces, includes management interface, and SVI's, etc...
        else:
            self.IfNumber=1
        self.ifPhysAddress=[]
        self.ifPhysAddress=self.GET_IF_MAC()


    def GET_DESC(self):
        return self.sysDescr[1]
    def GET_ID(self):
        return self.sysObjectID[1]
    def GET_UPTIME(self): #uptime is gathered in hundreths of a second and converted to day, hours, etc here
        self.sysUpTime = SNMP_V2MIB_GET(self.HOST, self.COMMUNITY, 'sysUpTime', 0)
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
        self.sysName = SNMP_V2MIB_GET(self.HOST, self.COMMUNITY, 'sysName', 0)
        if self.sysName is not None:
            return self.sysName[1]
        else:
            return "No Name"

    def GET_IFNUM(self): #number if interfaces, this is not perfect, for instance the hirschmann management interface shows up as int 85 despite there being only 11 on that switch
        if self.IfNumber is not None:
            return self.IfNumber
        else:
            return 1
    def GET_IF_MAC(self): #gets MAC of interfaces in 0x Hex Format
        x=0
        while x < int(self.IfNumber):
            if SNMP_OID_GET(self.HOST,self.COMMUNITY,'.1.3.6.1.2.1.2.2.1.6.' + str(x+1)) is not None:
                self.ifPhysAddress.append(SNMP_OID_GET(self.HOST,self.COMMUNITY,'.1.3.6.1.2.1.2.2.1.6.' + str(x+1))[1])
                #print(self.ifPhysAddress[x])
                x+=1
            else:
                x+=1
    def GET_OID(self,OID):
        return SNMP_OID_GET(self.HOST,self.COMMUNITY,OID)








class NET_DISC: #network discovery via nmap
    def __init__(self,NET,MASK):
        self.NETWORK=NET
        self.NETMASK=MASK
        self.nm = nmap.PortScanner()
    def DISCOVER(self):
        nNET=self.NETWORK + "/" + self.NETMASK
        self.nm.scan(hosts=nNET, arguments='-n -sP -PE -PA21,23,80,3389,22,443')
    def GET_NET(self):
        return self.nm.all_hosts()


##########################################################################################
#############################TEST CODE####################################################

#network=NET_DISC('192.168.127.48','24')
#network.DISCOVER()


#x=0
#DEVICE = []
#for host in network.GET_NET():
#    print('----------------------------------------------------')
#    print('Host : %s (%s)' % (host, network.nm[host].hostname()))
#    print('State : %s' % network.nm[host].state())
#    DEVICE.append(SNMP_OBJECT(host, 'public'))
#    print('NAME' + " " + DEVICE[x].GET_NAME())
#    x+=1

#print(len(DEVICE))


print(SNMP_MIB_WALK('192.168.127.52','public','LLDP-MIB','lldpRemTable'))






