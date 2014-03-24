#!/usr/bin/env python
# vim: set fileencoding=utf-8:
import ConfigParser
import logging
#import MySQLdb
import os
import sys
import time
import datetime

import subprocess
import threading

#import socket
import simplejson as json
from optparse import OptionParser
#from sqlalchemy.ext.sqlsoup import SqlSoup


OUT_PORT_NAME = 'int-br-eth2'
OUT_PORT = "0"
EXT_PORT = "eth2"
ports = {}
#ports = {port_name : Port_Info}
guarantees = {}
ip_ports = {}
#ip_ports[ip.ip] = {"port_name":ip.port_name, "host_ip":ip.host_ip}
supressions = {}
#server_ip = ""
#server_port = ""
#my_ip = ""
#db_url = ""
supression = {}


class Flow_Info:
    def __init__(self):
        self.src_host = ""
        self.dst_host = ""
        self.src_ip = ""
        self.dst_ip = ""

    def set_host(self, src, dst):
        self.src_host = src
        self.dst_host = dst


def PreConfigure():
    global guarantees
    global ip_ports
    global server_ip
    global server_port
    global db_url
    global my_ip
    #Reading the ini file to get both server connection and SQL connections
    config_file = "agent.ini"
    config = ConfigParser.ConfigParser()
    try:
        config.read(config_file)
    except Exception, e:
        print "Exception: Could not parse agent config file"
        LOG.error("Unable to parse config file \"%s\": %s"
                  % (config_file, str(e)))
        raise e
    server_ip = ""
    server_port = ""

    # Get Dwarf-server parameters and sql_url
    try:
        server_ip = config.get("SERVER", "server_ip")
        server_port = config.get("SERVER", "server_port")
        db_url = config.get("SQL", "sql_connection")
        my_ip = config.get("AGENT", "agent_ip")
    except Exception, e:
        pass
    print "readed: server :" + server_ip + "and port: " + server_port
    print "db_url : " + db_url


    #This is to get all guarantees from the sql in the dwarf-server
    options = {"sql_connection": db_url}
    db = SqlSoup(options["sql_connection"])
    port_g = db.port_guarantee.all()
    ips = db.ip_port.all()
    db.commit()
    for port in port_g:
            guarantees[port.port_name]={'0':port.guarantee}
    for ip in ips:
        ip_ports[ip.ip] = {"port_name":ip.port_name, "host_ip":ip.host_ip}
    print guarantees
    print ip_ports

    myfile = file("testit.txt", 'w')

def run_cmd(args):
    return subprocess.Popen(args, stdout=subprocess.PIPE).communicate()[0]

def run_vsctl(args):
    full_args = ["ovs-vsctl"] + args
    return run_cmd(full_args)

def run_dpctl(args):
        full_args = ["ovs-dpctl"] + args
        return run_cmd(full_args)

def get_taps():
    args = ['list-ports', 'br-int']
    result = run_vsctl(args)
#    return [i for i in result.strip().split('\n') if i.startswith('tap')]
    return result

def run_tc(args):
    full_args = ["tc"] + args
    return run_cmd(full_args)


def tc_tap_change(pid, rate):
    print "tc----------"+ pid
    classid = "1:"+ str(pid)
    rate = str(rate / 1000)+"kbit" 
    os.popen("tc class change dev "+ EXT_PORT + ' parent 1:1 classid ' + classid + ' htb rate ' + str(rate))
#tc class change dev eth1 parent 1:1 classid 1:6 htb rate 600mbit
#tc filter add dev $1 protocol ip parent 1:0 prio 2 u32 match ip dst 192.168.2.0/24 flowid 1:8

def init_tc():
    for port in ports:
        port_name = port
        pid = ports[port].port_id
        classid = "1:"+str(pid)
        port_ip = ""
        print "tc:"+classid
        for ip in ip_ports:
            if ip_ports[ip]["port_name"] == port_name:
                port_ip = ip
        if port_ip != "":
            print "examing~~~~"
            cmd = "tc class show dev "+ EXT_PORT +" | grep "+ classid +" | wc -l"
            print cmd
            tmp = os.popen(cmd).read()
            if int(tmp) <= 0:
                cmd = "tc class add dev "+ EXT_PORT + ' parent 1:1 classid ' + classid + ' htb rate 5000'
                os.popen(cmd)
            flow_tmp = os.popen("tc filter show dev "+ EXT_PORT +" | grep "+ classid +" | wc -l").read()
            print flow_tmp
            if int(flow_tmp) <= 0:
                print "adding this flowid"
                cmd = "tc filter add dev "+ EXT_PORT + " protocol ip parent 1:0 prio 2 u32 match ip src "+ port_ip +" flowid "+ classid
                print cmd
                os.popen(cmd)

def tc_flow_change(pid, flow_ip, rate):
    flow_id = "1:"+pid + flow_ip.split(".")[-1]
    rate = str(rate / 1000)+"kbit"
    tmp = os.popen("tc class show dev "+ OUT_PORT +" | grep "+ flow_id +" | wc -l").read()
    




def set_db_attribute(table_name, record, column, value):
    args = ["set", table_name, record, "%s=%s" % (column, value)]
    return run_vsctl(args)

def set_interface_ingress_policing_rate(record, value):
    set_db_attribute('Interface', record, 'ingress_policing_rate', int(value))
    set_db_attribute('Interface', record, 'ingress_policing_burst', int(value / 10))

def clear_db_attribute(table_name, record, column):
    args = ["clear", table_name, record, column]
    return run_vsctl(args)
############################################
#Class: Ports and Flows
class PortInfo:
    
    def __init__(self, pid="0",name='tap0'):
        self.port_id = pid
        self.port_name = name
        self.tx_bytes = []
        self.rx_bytes = []
        self.tx_rate = 0
        self.rx_rate = 0
        self.guarantee = 0
        self.rx_guarantee = 0
        self.tx_cap = 1000
        self.rx_cap = 1000
        self.flows = {}
        self.in_flows = {}
        self.flow_txg = {}
        self.flow_rxg = {}
        #flow_txg = dstIP:guarantee
        #flow: {dstIP:[bytes, rate, cap]}
        #in_flow: {srcIP:[bytes, rate]}
# For flow: inpoty:6,dstIP:192.168.1.18 ---> in TC:      class_id = 1:6   flow_id = 1:618

    def UpdateTxRate(self, tx):
        if len(self.tx_bytes) > 2:
            self.tx_bytes.pop(0)
        self.tx_bytes.append(int(tx))
        rate = [-1]
        for i in xrange(len(self.tx_bytes) - 1):
            rate.append(self.tx_bytes[i + 1] - self.tx_bytes[i])
        rate.sort()
        #rate_max = self.tx_bytes[-1] - self.tx_bytes[-2]
        #if self.tx_cap >= 0 and rate_max > self.tx_cap:
        #    rate_max = self.tx_cap
        rate_max = rate[-1] * 8
        self.tx_rate = rate_max
        #if self.port_name =='tapbbb7fbd5-c8':
        #       myfile = open('txrate.txt', 'a')
        #       myfile.write("%s\n" %rate_max)
        #       myfile.close()

#    def UpdateRxRate(self, rx):
#        if len(self.rx_bytes) > 2:
#            self.rx_bytes.pop(0)
#        self.rx_bytes.append(int(rx))
#        rate = [-1]
#        for i in xrange(len(self.rx_bytes) - 1):
#            rate.append(self.rx_bytes[i + 1] - self.rx_bytes[i])
#        rate.sort()
#       rate_max = rate[-1] * 8
#        self.rx_rate = rate_max
    def UpdateRxRate(self):
        self.rx_rate = 0
        for flow in self.in_flows:
            self.rx_rate += int(self.in_flows[flow].tx_rate)

    def UpdateRates(self, tx, rx):
        self.UpdateTxRate(tx)
        self.UpdateRxRate()
        
    def add_flow(self,srcIP, dstIP,tx_byte):
        if dstIP in self.flows:
            self.flows[dstIP].add_txbyte(tx_byte)
        else:
            self.flows[dstIP] = FlowInfo(srcIP,dstIP)
            self.flows[dstIP].add_txbyte(tx_byte)

    def add_in_flow(self, srcIP, dstIP,tx_byte):
        if srcIP in self.in_flows:
            self.in_flows[srcIP].add_txbyte(tx_byte)
        else:
            self.in_flows[srcIP] = FlowInfo(srcIP, dstIP)
            self.in_flows[srcIP].add_txbyte(tx_byte)

	
 

    def cap_flows(self):
        print "start capping flows"
        used = 0.0
        over = 0.0
        spare = 5000
        total = self.tx_cap
        for fid in self.flows:
            print "flow for cap :",fid
            self.flows[fid].update()
            tx = self.flows[fid].rate * 8
            if fid in self.flow_txg:
                guarantee = self.flow_txg[fid] * 1000 ** 2
            else:
                guarantee = 0
            if tx <= guarantee:
                used += tx * 1.25 + spare
            else:
                used += tx
                over += tx - guarantee
            if over <= 0:
                over = used 
        for fid in self.flows:
            if fid in self.flow_txg:
                guarantee = self.flow_txg[fid] * 1000 ** 2
            else:
                guarantee = 0
            rate = self.flows[fid].rate * 8
            cap = guarantee
            if rate  > guarantee:
                cap = min(total, max(guarantee, (rate + max(0, rate - guarantee) / over * (total  - used))))
            else:
                #cap = rate * 1.25 + spare
                cap = guarantee + spare
            self.flows[fid].tx_cap = cap
            print "flow ------:", fid
            print "rate :", self.flows[fid].tx_rate 
            print "cap  :", self.flows[fid].tx_cap

        

class FlowInfo:
    def __init__(self,srcIP,dstIP):
        self.dst_ip = dstIP
        self.src_ip = ""
        self.tx_bytes = [0,0]
        self.tx_rate = 0
        self.tx_cap = 0


    def add_txbyte(self,tx):
        if len(self.tx_bytes) > 2:
            self.tx_bytes.pop(0)
        self.tx_bytes.append(int(tx))
        rate = [-1]
        for i in xrange(len(self.tx_bytes) - 1):
            rate.append(self.tx_bytes[i + 1] - self.tx_bytes[i])
        rate.sort()
        rate_max = rate[-1] * 8
        self.tx_rate = rate_max
        

    def update(self):
        self.rate = self.tx_byte[1]-self.tx_byte[0]
        if self.rate <= 0:
            self.rate = 0
        self.tx_byte.pop(0)
 
    



######################################################################
#New ways to get ports and traffic statistics 

def get_ports():
        global ports
        global OUT_PORT
        global OUT_PORT_NAME
        args = ['show', '-s']
        raw_port = run_dpctl(args)
        port_map = {}
        #    return [i for i in result.strip().split('\n') if i.startswith('tap')]
        for i in raw_port.strip().split('port'): #for every port
            port_info = i.split('\t\t')
            port_id = port_info[0].split(':')[0]
            port_id = port_id[1:] 
            port_name = port_info[0].split(':')[1][1:].split(' ')[0]
			#tapa185c58a-64 (internal)
            if port_name.endswith('\n'):
                port_name = port_name[:-1]
            port_traffic = port_info[-1].split(' ')
                #['RX', 'bytes:27716431', '(26.4', 'MiB)', '', 'TX', 'bytes:2301368922', '(2.1', 'GiB)\n\t']
            rx = port_traffic[1].split(':')[-1]
            tx = port_traffic[-3].split(':')[-1]
            if tx=='':
                tx = '0'
            if rx == '':
                rx = '0'
            
            if port_name in ports:
                ports[port_name].UpdateRates(rx, tx)
		#print "already there:"+port_name+":"+ str(ports[port_name].tx_rate)
            else:
                if port_name.startswith("tap"):
                    ports[port_name] = PortInfo(port_id,port_name)
                    ports[port_name].UpdateRates(rx, tx)
                
#guarantees = {'tap44e21c13-40':[200,{192.168.1.18:150}], 'tap840158bf-03':[600,{192.168.2.10:500}]}

        return raw_port

def get_flows():
    for port_name in ports:
        tmp = os.popen("ovs-dpctl dump-flows| grep 'in_port(" + ports[port_name].port_id +")'").read()
	print tmp
        for flow in tmp.split("\n"):
            flow_info = flow.split(",")
            flow_dst = ""
            flow_byte = ""
            for info in flow_info:
                if info.startswith("ipv4"):
                    flow_src = info.split("=")[-1]
                    flow_dst = flow_info[(flow_info.index(info) + 1)].split("=")[-1]
                if info.startswith(' bytes'):
                    flow_byte = info.split(":")[-1]
            if flow_dst != "":
                ports[port_name].add_flow(flow_src, flow_dst, flow_byte)      
                print "adding flows from get flow:", flow_dst
        
def get_inflows():
    global ports
    global ip_ports
    cmd = "ovs-dpctl dump-flows| grep 'in_port(" + OUT_PORT +")' | grep 192.168"
    #print cmd
    tmp = os.popen(cmd).read()
    #print tmp
    for flow in tmp.split("\n"):
        flow_info = flow.split(",")
        flow_src = ""
        flow_dst = ""
        flow_byte = ""
        for info in flow_info:
        #get flow src ip and byte info
            if info.startswith("ipv4"):
                flow_src = info.split("=")[-1]
                flow_dst = flow_info[(flow_info.index(info) + 1)].split("=")[-1]
                print "in_flow: src--" + flow_src + "dst--" + flow_dst
            if info.startswith(' bytes'):
                flow_byte = info.split(":")[-1]
        #write new bytes info into port-flow 
        if flow_dst in ip_ports:
            print "flow_stc in ip_ports list"
            dst_port_name = ip_ports[flow_dst]["port_name"] 
            print dst_port_name
            if dst_port_name in ports:
                print "adding flows now!!!"
                ports[dst_port_name].add_in_flow(flow_src, flow_dst, flow_byte)

#######################################################################


def update_port_caps():
    global ports
    global guarantees
    used = 0.0
    over = 0.0
    spare = 5000
    total = 1000 ** 3
    for port in ports:
        #print "-----------"
        #all in bits
        tx = ports[port].tx_rate
        guarantee = ports[port].guarantee * 1000 ** 2
        if tx <= guarantee:
            used += tx * 1.25 + spare
        else:
            used += tx
        over += tx - guarantee
    if over <= 0:
        over = used
    for port in ports:
        guarantee = ports[port].guarantee * 1000 ** 2
        cap = guarantee
        rate = ports[port].tx_rate
        if rate  > guarantee:
            cap = min(total, max(guarantee, (rate + max(0, rate - guarantee) / over * (total  - used))))
        else:
            #cap = rate * 1.25 + spare
            cap = guarantee + spare
        ports[port].tx_cap = cap
        if port in supressions:
            print "capping supression "
            cap = cap * ( 1 - int(supressions[p_name])/100) + spare
        print "Port:   " + port
        print "rate ", (rate)
        print "cap  ", (cap)
        tc_tap_change(ports[port].port_id,cap)
        #set_interface_ingress_policing_rate(tap, cap)

def update_flow_caps():
        global ports
        for port in ports:
                ports[port].cap_flows()
    
def in_flow_feedback():
        #print the flow rate
    retrive = 0
    sup_flag = 0
    credit = 0
    used = 0
    total = 1000 ** 3
    supression = 0
    for port in ports:
        guarantee = ports[port].guarantee * 1000 ** 2
        rx = ports[port].rx_rate
        used += rx
        if rx > 5000000 and rx < guarantee:
            credit += guarantee
            sup_flag = 1
        else:
            credit += rx

    if sup_flag != 0 and (total<credit):
        over = credit - total
        supression = int(over/used * 100)
        print "credit "+ str(credit)
        print "supression "+ str(supression)
        #send supression message to dwarf_server
        for port in ports:
            guarantee = ports[port].guarantee * 1000 ** 2
            rx = ports[port].rx_rate
            for flow in ports[port].in_flows:
                    if ports[port].in_flows[flow].tx_rate > guarantee:
                    #send the signal
                        send_flow = {"src_ip":flow, "supression":supression}
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
                        sock.connect((server_ip, int(server_port)))  
                        sock.send(json.dumps(send_flow))  
                        print sock.recv(1024)  
                        print send_flow
                        print json.loads(json.dumps(send_flow))
                        sock.close()  

def getSupression():
    global db_url
    global supressions
    global ports
    global ip_ports
#This is to get all guarantees from the sql in the dwarf-server
    options = {"sql_connection": db_url}
    db = SqlSoup(options["sql_connection"])
    sup_info = db.supression.all()
    c_time = int(time.time())
    db.commit()
    for sup in sup_info:
        src_ip = sup.src_ip
        port_name = ip_ports[src_ip]["port_name"]
        print "getting db"
        print port_name
        for pid in ports:
            if port_name == ports[pid].port_name:
                print "this supression is mine"
                supress = sup.supression
                o_time = sup.time
                if port_name in supressions:
                    if c_time < (o_time + 10):
                        print "wow, a new one!" 
                        supressions[port_name]=supress
                    else:
                        del supressions[port_name]

   
def main():
    global ports
    flows = []
    x = 0
    logging.basicConfig(filename='rate.log',format='%(asctime)s %(message)s',level=logging.DEBUG)
    logging.info("check this out")
    #PreConfigure()
    get_ports()
    get_flows()
    #print "initing tc"
    #init_tc()
    #print "done tc init"
    while True:
        #getSupression()
#	ts = time.time()
#	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
#	print st
        get_ports()
        get_inflows()       
	for port_id in ports:
	    print port_id
	    port_log=ports[port_id]
	    logging.info('%s,%s', port_id,port_log.tx_rate)
	    for flow_id in port_log.flows:
		print flow_id
		flow_log = port_log.flows[flow_id]
		logging.info('%s,%s', flow_id,flow_log.tx_rate)
	
    #    update_port_caps()
    #    in_flow_feedback()
    #    update_flow_caps()
        for port_id in ports:
           if ports[port_id].port_name == "tapbbb7fbd5-c8":
               myfile = open('txrate.txt', 'a')
               myfile.write("%s %s\n" %(x,ports[port_id].tx_rate))
               myfile.close()
        x = x + 0.1
        time.sleep(1)

            

if __name__ == '__main__':
    main()
