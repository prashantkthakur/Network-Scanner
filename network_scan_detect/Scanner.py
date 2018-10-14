import pcap
import dpkt
import logging as log
import socket
from tabulate import tabulate
import time
import logging as log
class Scanner:
    def __init__(self,src,dst,protocol,port,sport):
        self.dst = dst
        self.src = src
        self.sport = sport
        self.type = {}
        self.allport =[port]
        self.horizontal = []
        if protocol == 'ICMP':
            self.data = {self.dst: {protocol:[]}}
            # log.debug("ICMP data in scanner class. data={}".format(self.data))
        elif protocol == 'TCP' or 'UDP':
            self.data = {self.dst: {protocol: set([port])}}
            # log.debug("TCP/UDP scanner data: {}".format(self.data))
        else:
            pass

    def update_data(self,src,dst,protocol,port,sport):
        # dst is hostIP
        # data = {hostIP:{protocol1:set([ports]),protocol2:set([ports])},
        #         hostIP:{protocol:set([ports])}}
        # Check for port as ICMP doesn't have port so None is added F.I. Ports:set([None]) --> Handled during display.
        self.allport.append(port)
        if not self.data.get(dst):
            # log.debug("New Host IP added to data.")
            self.data[dst] = {protocol: set([port])}
        else:
            if not self.data[dst].get(protocol):
                # log.debug("New Protocol added to data.")
                self.data[dst][protocol] = set([port])
            else:
                # log.debug("Updating existing host ip and protocol.")
                self.data[dst][protocol].add(port)

    # print object will give info on all its attribute
    def __repr__(self):
        return "data={}".format(self.data)
        # return "ScannerIP:{}, data={}".format(self.src,self.data)

class ScanDetect:
    def __init__(self, args):
        self.filename = args.filename
        self.iname = args.iname
        self.verbosity = args.verbosity
        self.timeout = args.timeout
        self.pNum = args.pNum
        self.hNum = args.hNum
        self.flw_timeout = args.flwTimeout
        self.offset = args.offset
        self.summary_data = dict()
        self.verbose_data = dict()
        self.all_scanners = {}  # { 'scanner_ip1': corresponding_Scanner_obj, 'scanner_ip2': corresponding_Scanner_obj}

    def check_protocol(self, val):
        mapping = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return mapping.get(val, None)

    # Supporting function to create port_range
    def _add_element(self,output,last, ports, i):
        if last != ports[i - 1]:
            output.append(str(last) + "-" + str(ports[i - 1]))
        else:
            output.append(str(last))

    # Takes list of ports and combine the ports in range format like 2-20
    def port_range(self,ports):
        ports.sort()
        last = None
        output = []
        for i, port in enumerate(ports):
            if (port - ports[i - 1]) > 1:
                self._add_element(output,last, ports, i)
            elif i > 0:
                continue
            last = port
        # last item is not included in the above iteration so run once again.
        self._add_element(output,last, ports, len(ports))
        return output

    # Returns IP in decimal format.
    def format_ip(self,ip):
        return socket.inet_ntoa(ip)

    # Extract src, dst, protocol and port info from the IP packet
    def _extract_info(self, ipData):
        src = self.format_ip(ipData.src)
        dst = self.format_ip(ipData.dst)
        # proto = lambda x: 'tcp' if x == 6 else 'udp' if x == 17 else '1' if x == 1 else None
        protocol = self.check_protocol(ipData.p)
        port = None if isinstance(ipData.data, dpkt.icmp.ICMP) else ipData.data.dport
        src_port = None if isinstance(ipData.data,dpkt.icmp.ICMP) else ipData.data.sport
        return {'src': src, 'dst': dst, 'protocol': protocol, 'port': port,'sport':src_port}

    def update_display(self,src,host,port):
        if not self.summary_data.get(src):
            # log.debug("New Host IP added to data.")
            self.summary_data[src] = {host: set(port)}
        else:
            if not self.summary_data[src].get(host):
                # log.debug("New Protocol added to data.")
                self.summary_data[src][host] = set(port)
            else:
                # log.debug("Updating existing host ip and protocol.")
                self.summary_data[src][host].update(port)

    def summary_print(self):
        '''Prints out summary of the output.
        Takes value from self.display_data (sorted values as per the condition match from Verbose print
        Computes protocol-port combination to get distinct port in each host and then sum them up.'''
        data = []
        # log.debug("PK Summary val:{}".format(self.summary_data))

        for src, val in self.summary_data.iteritems():
            host_num = len(self.summary_data[src].keys())
            port_num = 0
            for host, port in val.iteritems():
                port_num += len(val[host])
            data.append([src,host_num,port_num])

        print ("Summary:\n")
        print tabulate(data, ["Scanner", "#HostsScanned", "#PortsScanned"])

    # Return total num ports based on host. EG:{'srcip-hostip': 1005, '192.168.100.100': 1, '255.255.255.255': 1}
    def check_port(self):
        scanners = self.all_scanners
        port = {}
        for src_ip, value in scanners.iteritems():
            for host, proto in value.data.iteritems():
                pp = '{}-{}'.format(src_ip,host)
                port[pp] = 0
                for protocol in proto.keys():
                    port[pp] += len(list(proto[protocol]))
                    # log.warning(">>>check port host:{}; protocol:{}; port:{}".format(host,protocol,port))
        return port

    def prepare_summary_data(self,val):
        port = set()
        # host = set()
        pp = "{}-{}"
        log.warning("Summary print: i val={}".format(val))
        # if isinstance(i[3], set):
        for pt in val[3].pop():
            port.add(pp.format(val[1],pt))
        # if isinstance(i[3],str):
        #     port.append(pp.format(i[1],i[3]))
        # host.add(val[2])
        self.update_display(val[0],val[2],port)

    def prepare_verbose_data(self,val):
        port = val[3]
        if not self.verbose_data.get(val[0]):
            # log.debug("New Host IP added to data.")
            self.verbose_data[val[0]] = {val[2]: {val[1]:port}}
        else:
            if not self.verbose_data[val[0]].get(val[2]):
                # log.debug("New Protocol added to data.")
                self.verbose_data[val[0]][val[2]] = {val[1]:port}
            else:
                if not self.verbose_data[val[0]][val[2]].get(val[1]):
                    self.verbose_data[val[0]][val[2]][val[1]]=port
                else:
                # log.debug("Updating existing host ip and protocol.")
                    self.verbose_data[val[0]][val[2]][val[1]].update(port)

    def verbose_print(self,):
        # Tabulate FORMAT:  data = [[scannerIP, protocol, hostIp, ports],[scannerIP, protocol, hostIp, ports]]
        data = []
        self.__check_horizontal_scanner()
        scanners = self.all_scanners
        num_port = self.check_port()
        for src_ip, value in scanners.iteritems():
            port = []
            for host, proto in value.data.iteritems():
                pp = '{}-{}'.format(src_ip,host)
                for protocol in proto.keys():
                    port_output = self.port_range(list(proto[protocol])) if protocol != 'ICMP' else ' '
                    port.append(proto[protocol])
                    log.warning("VP: scanner.data={}".format(num_port))
                    log.warning("VerbosePrint pnum/hnum host:{} protocol:{} \n===> port={}\n--->num_port:{}".format(host,protocol,port,num_port))
                    if num_port[pp] >= self.pNum:
                        self.prepare_summary_data([src_ip,protocol,host,port])
                        self.prepare_verbose_data([src_ip,protocol,host,port])
                        port= []
                        if [src_ip, protocol, host, ', '.join(port_output)] not in data:
                            log.warning("VALUE in HRRRRR: {}".format(data))
                            data.append([src_ip, protocol, host, ', '.join(port_output)])
                        log.warning("Port num:data in verbose: {}".format([src_ip, protocol, host, ','.join(port_output)]))
                        # print "PORT VAL: {}".format(str([src_ip, protocol, host, port_output]))
                    else:
                        log.error(
                            "Unmatched Condition pNum Verbose;pnum:{},scnPort={}".format(self.pNum, num_port))
        log.warning("\nSSSSSSSSSSSSSSSSSSSSSSSSSS\nsummarydata={}".format(self.summary_data))
        for src_ip, value in scanners.iteritems():
            port = []
            for host, proto in value.data.iteritems():
                for protocol in proto.keys():
                    # port_output = self.port_range(list(proto[protocol])) if protocol != 'ICMP' else ' '
                    port.append(proto[protocol])
                    if len(value.horizontal) > 0:
                        for i in value.horizontal:
                            hport = []
                            myset = set()
                            if host in value.type[i]:
                                prtcol = i.split('-')[0]
                                port_val = i.split('-')[1] if i.split('-')[1] != 'None' else None
                                # pp = value.data[host][prtcol] if prtcol != 'ICMP' else ' '
                                myset.add(str(port_val))
                                hport.append(myset)
                                log.warning("HR check:{}".format([src_ip,prtcol,host,hport]))
                                # if prtcol != 'ICMP' and port_val not in list(value.data[host][prtcol]):
                                if len(self.summary_data) == 0 or (not self.summary_data.get(src_ip)) or (not self.summary_data[src_ip].get(host)) or (i not in list(self.summary_data[src_ip].get(host))):
                                    self.prepare_summary_data([src_ip,prtcol,host,hport])
                                    log.warn("HR verb-data BBBBBB: {}".format(data))
                                    # add_data = self.verbose_check([src_ip, prtcol, host, port_val])
                                    # if add_data:
                                    data.append([src_ip, prtcol, host, str(port_val) if port_val is not None else ' '])
                                    log.warn("HR verb-data: AAAAAAA {}".format(data))

                    else:
                        log.error(
                            "Unmatched Condition Hnum Verbose; hnum:{}: \n\t summary_data:{}".format(self.hNum,self.summary_data))
                    # data.append([srcIp,protocol,host,port_output])

        # NOTE: Activate the print statement to get the Verbose Summary description.
        # print ("Summary not activated. Skipped to include large number of ports info.")
        if self.verbosity:
            print tabulate(data,["Scanner", "Protocol", "HostScanned", "PortScanned"])
            self.summary_print()
        else:
            self.summary_print()

    def __check_horizontal_scanner(self):
        '''
        Creates a list of common ports hit for different hosts.
        '''
        scanner = self.all_scanners
        for scanner_ip, b in scanner.iteritems():
            for ht, val in b.data.iteritems():
                for p, pt in val.iteritems():
                    for port in pt:
                        pair = '{}-{}'.format(p, port)
                        if not b.type.get(pair):
                            b.type[pair] = [ht]
                        else:
                            b.type[pair].append(ht)
            # log.debug("__check_horizontal_scanner executed. Type:{}".format(b.type))

        for sip, b in scanner.iteritems():
            fnc=[lambda x: len(x)]
            b.horizontal =[]
            for key in b.type.keys():
                val = map(lambda x: x(b.type[key]), fnc).pop()
                # print "HZ: key:val={}:::{}".format(key,val)
                if val >= self.hNum:
                    b.horizontal.append(key)
            # log.debug("__check_horizontal_scanner executed. Horizontal: {}".format(b.horizontal))
        # print b.horizontal

    def check_return_pkt(self,info):
        pkt_return = True
        if len(self.all_scanners) == 0:
            pkt_return = False
        else:
            if info['dst'] in self.all_scanners.keys():
                # log.warning("dst present in scanner.")
                for scanner_ip, obj in self.all_scanners.iteritems():
                    if info['src'] in obj.data.keys():
                        # log.warning("info-src present as host")
                        proto = obj.data.get(info['src'])
                        # log.warning("Check RPKT: info:{} \n===> obj data:{}".format(info,obj.data))
                        # check if the protocol is present and check. If not present: data is fresh.
                        if proto.get(info['protocol']) and info['sport'] in proto[info['protocol']]:
                            # log.warning("Returning packet.")
                            pkt_return = True
            else:
                pkt_return = False
        return pkt_return

    def pkt_analyzer(self,pkts,start=float('inf')):
        pkt_count = [0, 0, 0]
        start_time = 0
        end_time = 0
        offset_flow = set()

        for tstamp, pkt in pkts:
            if time.time() - start > self.timeout:
                raise Exception("Timeout")
                break
            pkt_count[0] += 1
            eth = dpkt.ethernet.Ethernet(pkt)
            ip_pkt = eth.data
            if self.filename and pkt_count[0] == 1:
                start_time = tstamp
                # log.warning("Start Time:{}".format(start_time))
            if isinstance(ip_pkt, dpkt.ip.IP):
                if isinstance(ip_pkt, dpkt.ip.IP) and self.filename and tstamp - start_time < self.offset:
                    # log.warning("PKT ANA: ip_pak:{}".format(ip_pkt.__repr__()))
                    # if isinstance(ip_pkt.data, dpkt.tcp.TCP) and ip_pkt.data.flags not in [20,18]:
                    info = self._extract_info(ip_pkt)
                    flow = "{}-{}-{}-{}".format(info['src'],info['dst'],info['protocol'],info['port'])
                    offset_flow.add(flow)
                    end_time = tstamp
                    # log.warning("End of offset. offset:{}   endtime={}".format(offset_flow,end_time))
                    continue

                if isinstance(ip_pkt, dpkt.ip.IP) and tstamp-end_time < self.flw_timeout:
                    info = self._extract_info(ip_pkt)
                    flow = "{}-{}-{}-{}".format(info['src'], info['dst'], info['protocol'], info['port'])
                    if flow in offset_flow:
                        # log.warning("Flow in offset flow={}".format(flow))
                        continue
                # if isinstance(ip_pkt, dpkt.ip.IP):
                if isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    icmp_type = 'request' if ip_pkt.data.type == 8 else 'reply'
                    if icmp_type == 'reply':
                        continue
                    info = self._extract_info(ip_pkt)

                    if info['src'] not in self.all_scanners:
                        new_scanner = Scanner(**info)
                        self.all_scanners[info['src']] = new_scanner
                    else:
                        self.all_scanners[info['src']].update_data(**info)
                        # log.debug("new_scanner content={}".format(new_scanner))
                    continue
                # Check for all TCP and UDP packets
                if isinstance(ip_pkt.data, dpkt.tcp.TCP) or isinstance(ip_pkt.data, dpkt.udp.UDP):
                    pkt_count[1] += 1
                    # Remove adding false entry which has SYN-ACK and RST-ACK flags
                    if isinstance(ip_pkt.data, dpkt.tcp.TCP) and ip_pkt.data.flags in [20, 18]:
                        continue
                    info = self._extract_info(ip_pkt)
                    pkt_return = self.check_return_pkt(info)
                    # log.warning("Different pkt. info:{}\n IPPKT:{}\npktreturn:{}".format(info, ip_pkt.__repr__(),pkt_return))
                    if not pkt_return:
                        if info['src'] not in self.all_scanners:
                            new_scanner = Scanner(**info)
                            self.all_scanners[info['src']] = new_scanner
                        else:
                            self.all_scanners[info['src']].update_data(**info)
                    else:
                        # src present in the host of another scanner so skip packet
                        continue
                else:
                    continue
            else:
                pkt_count[2] += 1
                # Skip payload packets as they are not any connection attempt they can be regular connection.
                continue
        log.info("Total={} #Non-ACK:{} #Non-IP:{}".format(*pkt_count))
        self.verbose_print()

    # Done: Implement -o/-S option for time offset
    def read_pcap(self,start):
        log.info("Reading the pcap file: %s", self.filename)

        # [total, non-ACK, non-IP, ACK-RST]
        while time.time() - start < self.timeout:
            try:
                with open(self.filename) as fp:
                    pkts = dpkt.pcap.Reader(fp)
                    self.pkt_analyzer(pkts,start)
                    return True
            except Exception as e:
                print ("Error reading file:{}; Error: {}".format(self.filename,str(e)))
                exit(1)
        raise Exception("Timeout")

    # Live-Sniffing of traffic
    def live_sniff(self,start):
        try:
            log.info("Starting sniffing at {};".format(time.strftime('%x-%X')))
            pc = pcap.pcap(name=self.iname, promisc=True, immediate=True)
            count = 0
            pkts = []
            fp = open('pkt.pcap', 'wb')
            st = start
            wt = dpkt.pcap.Writer(fp)
            for t, p in pc:
                count += 1
                pkts.append((t, p))
                wt.writepkt(p, t)
                if time.time() - st > self.timeout:
                    fp.flush()
                    fp.close()
                    wt.close()
                    break
            log.info("Done sniffing at {};".format(time.strftime('%x-%X')))
            with open('pkt.pcap') as fp:
                pkts = dpkt.pcap.Reader(fp)
                self.pkt_analyzer(pkts)
            return True
        except Exception as e:
            print ("Error sniffing interface {}; Error:{}".format(self.iname, str(e)))
            log.exception("Error sniffing interface {}; Error:{}".format(self.iname, str(e)))
            exit(1)