'''
Scan Detector - Detect the vertical and horizontal scanner by analyzing the network traffic from a saved pcap file or live sniffing.
Date: Sep, 2017
Professor: Dr. Lorenzo De Carli
Mini-Project for CS557 - Colorado State University
Author: Prashant K. Thakur
This method uses functions from the Scanner class.
The argument parser and the logging has been set in this method.
The main function invokes all the necessary functions from Scanner.py

'''

import argparse
import sys
import time


def setup_argparser():
    parser = argparse.ArgumentParser(conflict_handler='resolve')
    parser.add_argument("-V", "--verbosity", help="Verbosity option DEBUG", action="store_true", dest='verbosity')
    parser.add_argument('-t', '--timeout', help='App Timeout', action='store', dest='timeout',type=float, default=200)
    parser.add_argument('-p', '--pnum', help='Port Number', action='store', dest='pNum',type=int,default=float('inf'))
    parser.add_argument('-h', '--hnum', help='Host Number', action='store', dest='hNum',type=int, default=float('inf'))
    parser.add_argument('-S', '--flwtout', help='FlowTimeout(s)',default=60,type=int, action='store', dest='flwTimeout')
    parser.add_argument('-o', '--offset', help='Offset time', action='store', dest='offset', type=int)
    # Create exclusive group so that filename and interface can't be read simultaneously.
    exri = parser.add_mutually_exclusive_group()
    exri.add_argument("-r", '--filename', help='Filename', action='store', dest='filename')
    exri.add_argument("-i", '--interface', help='Interface Name', action='store', dest='iname')

    args = parser.parse_args()
    # Check if -o option is issued with -i. Through ValueError else process
    if args.offset >= 0 and args.iname:
        raise ValueError("Interface Name (-i) and offset time (-o) can't be used together.")
    return args


def main(argv):
    try:
        # Check if minimum number of arguments are passed. Mandatory -i/-r; -h; -p.
        # python scandetect.py -i eth0 ==> 3 arguments
        args = setup_argparser()
        # host_port = True if args.hNum and args.pNum else False
        iname_file = 'iname' if args.iname else 'filename' if args.filename else ''
        if len(argv) < 5 or iname_file == '':
            raise ValueError("Insufficient arguments passed!")
        if args.pNum == float('inf') and args.hNum == float('inf'):
            raise ValueError("Need to pass at least -p or -h to search scanner type.")
        # Extract arguments passed.
        # Monitor the pcap file.
        scanner = ScanDetect(args)
        start = time.time()
        # Read file for traffic
        if scanner.filename:
            scanner.read_pcap(start)

        if scanner.iname:
            scanner.live_sniff(start)

    except Exception as e:
        if str(e) == 'Timeout':
            print("Error executing command. Error: {};".format(str(e)))
        else:
            print ("Error: {}".format(str(e)))

# Deprecated by implementing custom module to print the required format.
# def install_dependencies():
#     import subprocess as sp
#     import json
#     with open('mainfest') as fp:
#         packages = json.load(fp)['req_packages']
#         for pkg in packages:
#             log.info("Checking dependencies for package {}".format(pkg))
#             pipe = sp.Popen(['pip','install','--user',pkg],stderr=sp.PIPE,stdout=sp.PIPE)
#             comm = pipe.communicate()
#             success = 'Successfully installed {}'
#             pre_installed = 'Requirement already satisfied'
#             if pre_installed in comm[0] or success.format(pkg) in comm[0]:
#                 print("Package installation validated.")
#                 continue
#             else:
#                 print("Error installing the package: {}; Error: {}".format(pkg,comm[0]))


if __name__ == '__main__':
    from Scanner import ScanDetect
    main(sys.argv)
