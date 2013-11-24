import sys
from subprocess import Popen, PIPE, STDOUT

hash = {} 
device = ""

def flowslice(btwsize):
#tcpslice +400 +5 /home/centos/Downloads/tcpdump_thursday -w out	 
   output = Popen(['tcpslice', '-d', device],stdout=PIPE)
   cap_start =  output.stdout.readline().split('\t')[1]
   cap_end = output.stdout.readline().split('\t')[1]

 
   btw_start = int(float(cap_start)) - (int(float(cap_start))%int(btwsize))
  
   print 'cap_start ' + str(cap_start)
   print 'btw_start ' + str(btw_start)

  
	 #while 1:
         #   command = 'tcpslice ' + '+' + str(btwsize) + ' +' + str(i)
                             
         #Popen(bashCommand.split(), stdout=subprocess.PIPE)
         #output = process.communicate()[0]

def flowstats():
   output = Popen(['tcpdump', 'ip', '-vnn' , '-q' , '-r' , device  ], stdout=PIPE)
   for (i, line) in enumerate(output.stdout):
      if i%2!=0:
         if ',' in line:
            key=line.split(',')[0]
         else:
            key=line.rsplit(' ',1)[0]
         if not key in hash:
            hash[key] = 1
         else:
            hash[key] +=1 
         
def display():
   for flow in hash:
      print flow + ' ' + str(hash[flow])   
   
	

if __name__ == "__main__":
   device = sys.argv[1]
   flowslice(sys.argv[2])
   flowstats()
   display()    	
