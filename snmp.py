from pysnmp.hlapi import *

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

def SNMP_LLDP_GET(HOST, COMMUNITY, VAR, INSTANCE):

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




class SNMP_OBJECT:
    def __init__(self,HOST,COMMUNITY):
        self.HOST=HOST
        self.COMMUNITY=COMMUNITY
        self.sysDescr=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysDescr',0)
        self.sysObjectID=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysObjectID',0)
        self.sysUpTime=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysUpTime',0)
        self.sysName=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysName',0)
    def GET_DESC(self):
        return self.sysDescr[1]
    def GET_ID(self):
        return self.sysObjectID[1]
    def GET_UPTIME(self):
        return self.sysUpTime[1]
    def GET_NAME(self):
        return self.sysName[1]

SWITCH1=SNMP_OBJECT('192.168.127.52','public')
print('NAME' + " " + SWITCH1.GET_NAME())
print('sys desc' + " " + SWITCH1.GET_DESC())
print('ID' + " " + SWITCH1.GET_ID())
print('UPTIME' + " " + SWITCH1.GET_UPTIME())

