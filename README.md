test_flowsense.py
=====================================
The test_flowsense.py is a program developed in python
to test the Flowsense App.

In order to test the Flowsense App we need:

1 - A BTW statistics file generated by the Flowsense App;
2 - The tcpdump file used by the Flowsense App to generate the statistics File;
3 - Specify the BTW Size used;
4 - Specify a directory to save intermediary results.


Basic Functionality of test_flowsense:
======================================

1 - Read tcpdump file and split it in n tcpdump files.
    (The split factor is determined by the Basic Time Window (BTW) Size.
    If the tcpdump file is 1000 seconds long and the BTW size is configure
    to be 10 seconds we will have 100 tcpdump files with 10 seconds worth
    of capture each.
    tcpslice is used to slipt the original tcpdump file.)

2 - Read each tcpdump file and calculate the number of packets for each flow.
    (We use tcpdump to read and output the flows. Each Flow (srcip.port > dstip.dstport proto)
    is used as a dictionary key, the value is the number of packets observed for that flow.)

3 - Read the output statistics per BTW file from the Flowsense App.

4 - Create a Dictionary using the statistics file as described in step 2.

5 - Compare both dictionaries, highlight any error or mismatch between both dictionaries



Run test_flowsense  
======================================

1-python ./test_flowsense.py tcpdump_file btw_size tcpdump_results_dir statistics.csv

2-Run ./test_bash script:
    
    2.1- Here is how the  script operates:
        
        2.1.1 Get a random tcpdump slice out of a provided tcpdump file

        2.1.2 Run Flowsense App using the random tcpdump slice and generate the statistics file

        2.1.3 Verify that the statistics File generated by the Flowsense App is correct using 
              ./test_flowsense.py
    
        2.1.4 Repeat this process for every btw size in BTW_SIZES list

    2.2- Please set the FLOWSENSE variable to point to the flowsense binary
    
    2.3- Please set the TEST_FLOWSENSE variable to point to the test_flowsense python executable

 


