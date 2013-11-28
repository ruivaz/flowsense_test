"""Unit Test Program for Flowsense"""
import flowsense
import unittest

class TestFlowsenseFunctions(unittest.TestCase):
    """ Unit Test Class """
    def setUp(self):
        """ Create Collection of BTWs """

        self.btw_size = 10
        self.stats_file = './stats.csv'
        self.tcpdump_file = './tcpdump_thursday_ip_only_900597090_to_900597149'
        self.result_dir = './testcase_dumps/'

        self.btw_collection_file = flowsense.readstats(self.stats_file)

        self.btw_collection = flowsense.flowslice(
            self.tcpdump_file,
            self.btw_size, self.result_dir)

        flowsense.flowstats(self.btw_collection)


    def flowslice(self):
        """ Test BTW Start Times and Device """
        for btw in self.btw_collection:
            print 'Start Time: ' + str(btw.start)
            print 'End Time: ' + str(btw.end)
            print 'Device: ' + str(btw.device)

    def flowstats(self):
        """ Test Number of Packets per Flow """
        #flowsense.flowstats(self.btw_collection)
        for btw in self.btw_collection:
            print 'Device: ' + str(btw.device) + '\n'
            for flow in btw.hashmap:
               print flow + ' ' + str(btw.hashmap[flow])

        for btw in self.btw_collection_file:
            print 'Device: ' + str(btw.device) + '\n'
            for flow in btw.hashmap:
               print flow + ' ' + str(btw.hashmap[flow])


    def test_compare(self):
        """ Compare the BTW Object list between
        the Statistics File and Script """
        #print len(self.btw_collection)
        #print len(self.btw_collection_file)
        print flowsense.test(self.btw_collection, self.btw_collection_file)


if __name__ == '__main__':
    unittest.main()
