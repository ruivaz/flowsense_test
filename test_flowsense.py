"""This script was created to test the Flowsense C Application
Basically we calculate the number of packets for each flow
in a defined time window based on a tcpdump file

Make sure that the tcpdump file passed as an argument contains only
ip traffic, since Flowsense only calculates stats for IP Traffic
Use tcpdump ip -r tcpdump -w ip_only_tcpdump"""

import sys
from subprocess import Popen, PIPE

HASH = {}
BTWS = []


class Btw:

    """BTW Class Represent a Basic Time Window"""

    def __init__(self, btw_start, btw_end, device):
        self.start = btw_start
        self.end = btw_end
        self.device = device
        self.hashmap = {}


def flowslice( device, btw_size, output_dir):

    """ This method slices a tcpdump file in n tcpdump files
    Each resulting file has a time range equal to btw_size
    We are using tcpslice, here's and example of how to run tcpslice:
    tcpslice +400 +5 /home/centos/Downloads/tcpdump_thursday -w out """

    #List containing collection of BTW Objects
    btw_collection = []

    #Get start and end time of capture from tcpdump file
    output = Popen(['tcpslice', '-R', device], stdout = PIPE)
    line = output.stdout.readline()
    cap_start = float(line.split('\t')[1])
    cap_end = float(line.split('\t')[2])


    #Calculate the starting basic time window start
    btw_start = int(float(cap_start)) - (int(float(cap_start)) % btw_size)

    #Calculate the time range of the capture
    cap_range = cap_end - cap_start

    #Time offset since the start time of capture
    btw_offset = round(float(btw_start + btw_size) - cap_start, 6)

    #Slice the tcpdump file into n resulting tcpdump files with a
    # time range defined by btw_size
    i=0
    while btw_offset < cap_range+btw_size:
        #Create and Add Btw to BTW object list
        output_file = output_dir + 'example_' + str(int(btw_offset / btw_size))
        btw_collection.append(Btw(btw_start + (i*btw_size) , btw_start +((i+1)*btw_size)
                     , output_file))

        #print 'tcpslice +' + str(btw_offset) + ' +' + str(btw_size) + '
        #       device' + ' -w ' + str(output_file)

        if btw_offset < btw_size:
            #Slice tcpdump file
            output = Popen(['tcpslice', '+' + '0', '+' + str(btw_offset),
                        device, '-w', output_file], stdout = PIPE)
        else:
            #Slice tcpdump file
            output = Popen(['tcpslice', '+' + str(btw_offset-btw_size),
                        '+' + str(btw_size), device, '-w', output_file],
                        stdout = PIPE)
        btw_offset += btw_size
        i+=1

    return btw_collection


def flowstats(btw_collection):

    """ This method calculates the number packets for each flow.
    A flow is defined by the following tuples (src IP, dst IP, src Port,
    dst Port, Protocol )"""

    for btw in btw_collection:
        output = Popen(['tcpdump', 'ip', '-vnn' , '-q', '-r', btw.device  ],
                       stdout = PIPE)
        #Make sure we don't get a duplicate packet
        ids={}
        l=0
        for i, line in enumerate(output.stdout):
            if i % 2 == 0:
                proto = line[line.find('(', 60)+1:line.find(')')]
                if not line[0].isdigit():
                    proto = -1
            else:
                if proto != -1:
                    l+=1
                    key = (line.split(':')[0] + ' ' + proto).strip()
                    if not key in btw.hashmap:
                        btw.hashmap[key] = 1
                    else:
                        btw.hashmap[key] += 1
        output.terminate()


def readstats(filepath):

    """ This method reads the output file from the Flowsense App
    and creates a list of BTW Objects. This list is later going to be
    compared to the list created using tcpslice and tcpdump"""

    #List containing collection of BTW Objects
    btw_collection = []

    prev_btwstart = 0
    with open(filepath, 'r') as statsfile:
        for i, line in enumerate(statsfile):
            # Skip first line with meta-info
            if i != 0:
                elems = line.split(',')
                if len(elems) != 11:
                    print "Error: Stats File Should Have the following Format:" + '\n' \
                    + "messageLength, type, btwStartSeconds, btwEndSeconds, sourceIPv4Address, \
destinationIPv4Address, sourceTransportPort, \
destinationTransportPort, protocolIdentifier, \
packetDeltaCount, octetDelta" + '\n' + "Check Statistics File Line: " + str(i)
                    return -1
                # If this is the beginning create a new Btw object
                if prev_btwstart == 0:
                    btw = Btw(elems[2] , elems[3], filepath)
                    prev_btwstart = elems[2]

                # If a new BTW create a new Btw object and add previous to list
                elif elems[2] != prev_btwstart:
                    btw_collection.append(btw)
                    btw = Btw(elems[2] , elems[3], filepath)
                    prev_btwstart = elems[2]

                if elems[6] == '0':
                    key = elems[4] + ' ' + '>' + ' ' +elems[5] + ' ' + elems[8]
                    btw.hashmap[key] = int(elems[9])
                else:
                    key = elems[4] + '.' + elems[6] + ' ' + '>' + ' ' \
                        +elems[5] + '.' + elems[7] + ' ' + elems[8]
                    btw.hashmap[key] = int(elems[9])

    btw_collection.append(btw)


    return btw_collection


def test(btw_collection, btw_collection_file):

    """ Verify if the two Collection of BTW are equal
        If so then the Unit Test is Returns with Status OK """

    status = 'OK'

    print ''
    print ''
    print '++++++++++++++++++++++++Begin Test+++++++++++++++++++++++++++'
    print 'BTW Size: ' + str(btw_collection[0].end - btw_collection[0].start)
    print 'Flowsense Statistics: ' + btw_collection_file[0].device

    if len(btw_collection) != len(btw_collection_file):
        return 'Error: Number of BTWs between stats file and proof differs'
    else:
        for i in range(len(btw_collection)):
            print '========================================================'
            print 'BTW Start: ' + str(btw_collection[i].start)
            print 'BTW End: ' + str(btw_collection[i].end)
            status = dics_equals(btw_collection[i].hashmap,
                    btw_collection_file[i].hashmap)
            if status != 'OK':
                return status

    print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
    print '-------------------------------------------------------------'
    return 'All Tests Passed - Success'

def dics_equals(dic1, dic2):

    """ Test if two Dictionaries match,
        If they don't match find where's
        the mismatch """

    print 'Number of Flows in Proof Dictionary ' + str(len(dic1))
    print 'Number of Flows calculated by FlowSense ' + str(len(dic2))
    #If the number of shared items between the two dics is equal
    #to the size of the dictionaries, the dictionaries are identical

    shared_items = set(dic1.items()) & set(dic2.items())
    print 'Number of Equal Flows between Proof and Flowsense ' + str(len(shared_items))

    if len(shared_items) != len(dic1) or len(shared_items) != len(dic2):
        for key in dic1:
            try:
                dic2[key]
            except KeyError:
                return 'Error: Flow : ' + key + \
                    ' does not exist in Statistics File'
            if dic1[key] != dic2[key]:
                print dic1[key]
                print dic2[key]
                return 'Error: Number of Packets in Flow: ' + key + \
                    ' differs'

        for key in dic2:
            try:
                dic1[key]
            except KeyError:
                return 'Error: Flow : ' + key + \
                    ' does not exist in Proof File'

    else:
        return 'OK'



def display():

    """This method display the flow stats calculated by btw"""

    for btw in BTWS:
        for flow in btw.hashmap:
            print flow + ' ' + str(btw.hashmap[flow])

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""

if __name__ == "__main__":

    print sys.argv[1]

    btw_size = int(sys.argv[2])
    stats_file = sys.argv[4]
    tcpdump_file = sys.argv[1]
    result_dir = sys.argv[3]

    #Read Output BTW File from Flowsense
    btw_collection_file = readstats(stats_file)

    #Use Flowslice to slice tcpdump in n tcpdumps with btw_size time interval
    btw_collection = flowslice(
            tcpdump_file,
            btw_size, result_dir)

    #Calculate the BTW Statistics using tcpdump
    flowstats(btw_collection)


    #Compare the Output BTW File from Flowsense with the Calculate BTW File
    print test(btw_collection, btw_collection_file)
    print '-------------------------------------------------------------'
