#!/usr/bin/env python2
import sys
import os
from datetime import datetime



def get_ip_addr(number, pfx_size):
 if (number == 0 and pfx_size == 0):
  return "any"

 ip_add = ""
 for i in range(4):
  ip_add += str(number // (256**(4-i-1))) + "."
  number = number % (256**(4-i-1))
 ip_add = ip_add[0:len(ip_add)-1]
 ip_add += "/" + str(pfx_size)
 return ip_add

def get_ip_addr_without_mask(number):
 if (number == 0 and pfx_size == 0):
  return "any"

 ip_add = ""
 for i in range(4):
  ip_add += str(number // (256**(4-i-1))) + "."
  number = number % (256**(4-i-1))
 ip_add = ip_add[0:len(ip_add)-1]
 return ip_add


def parse_port(port):
 if (port == ">1023"):
  return "1023"
 if (port == "any"):
  return "0"
 try:
  a = int(port)
 except:
  return False

 return port

def get_port(port):
 port = int(port)
 if (port == 1023):
  return ">1023"
 if (port == 0):
  return "any"
 return str(port)

def get_port_logs(port):
 port = int(port)
 if (port == 0):
  return "None"
 return str(port)



def main():
 if (len(sys.argv)<2):
  print "Not enought arguments"
  return -1
 if (sys.argv[1] == "load_rules"):
  if (len(sys.argv) == 3):
   if (check_exists("/sys/class/fw/rules/rules", "Module") and check_exists(sys.argv[2], "Rules file")):
    Rules = ""
    lineNumber = 0
    f = open(sys.argv[2], 'r')
    line = f.readline()
    while line:
     lineNumber = lineNumber + 1
     line = line.replace("\n", "")
     Items = line.split()

     if not "".join(Items):
      line = f.readline()
      continue

     if (len(Items) != 9):
      print "Not enought arguments in line " + str(lineNumber)
      return -1

     if (len(Items[0]) > 19):
      print "Name of the rule too long in line " + str(lineNumber)
      return -1

     if not (Items[1] in Directions):
      print "Not legal direction in line " + str(lineNumber)
      return -1
     Items[1] = str(Directions.index(Items[1]) + 1)

     Items[2] = parse_ip_addr(Items[2])
     if (not Items[2]):
      print "Illegal ip address at line " + str(lineNumber)
      return -1

     Items[3] = parse_ip_addr(Items[3])
     if (not Items[3]):
      print "Illegal ip address at line " + str(lineNumber)
      return -1

     if (not Items[4] in Protocols.keys()):
      print "Illegal protocol in line " + str(lineNumber)
      return -1
     Items[4] = Protocols[Items[4]]

     Items[5] = parse_port(Items[5])
     if (not Items[5]):
      print "Illegal port in line " + str(lineNumber)
      return -1

     Items[6] = parse_port(Items[6])
     if (not Items[6]):
      print "Illegal port in line " + str(lineNumber)
      return -1

     if (Items[7] not in Ack.keys()):
      print "Illegal ack number in line " + str(lineNumber)
      return -1
     Items[7] = Ack[Items[7]]

     if (Items[8] not in Actions.keys()):
      print "Illegal action in line " + str(lineNumber)
      return -1
     Items[8] = Actions[Items[8]]

     Rules = Rules + " ".join(Items) + "\n"
     line = f.readline()

    if (len("".join(Rules.split())) == 0):
     Rules = "Clear Rules"
    with open("/sys/class/fw/rules/rules", 'w') as rules_module:
     rules_module.write(Rules)
    f.close()
  else:
   print "Wrong number of arguments"
   return -1

 elif (sys.argv[1] == "show_rules"):
  if (len(sys.argv) == 2):
   if check_exists("/sys/class/fw/rules/rules", "Module"):

    Rules = ""

    with open("/sys/class/fw/rules/rules", 'r') as rules_module:
     if (not rules_module):
      print "Module does not exist!"
      return -1
     Rules_lines = []
     line = rules_module.readline()
     line = line.replace("\n","")
     while line:
      newItems = []
      Items = line.split(" ")
      newItems.append(Items[0])
      newItems.append(Directions[int(Items[1]) - 1])
      newItems.append(get_ip_addr(int(Items[2]), int(Items[3])))
      newItems.append(get_ip_addr(int(Items[4]), int(Items[5])))
      newItems.append(rProtocols[Items[6]])
      newItems.append(get_port(Items[7]))
      newItems.append(get_port(Items[8]))
      newItems.append(rAck[Items[9]])
      newItems.append(rActions[Items[10]])
      Rules_lines.append(newItems)
      line = rules_module.readline()
      line = line.replace("\n","")
     
    Rules = "\n".join(["{:22} {:<5} {:<15} {:<15} {:<8} {:<10} {:<10} {:<5} {}".format(*S) for S in Rules_lines])
    print Rules

 elif (sys.argv[1] == "show_log"):
   Logs = ""

   with open("/dev/fw_log", 'r') as logs_module:
    if (not logs_module):
     print "Module does not exist!"
     return -1

    line = logs_module.readline()
    line = line.replace("\n","")
    log_lines = []
    while line:
     newItems = []
     Items = line.split(" ")
     timestamp = Items[0]
     newItems.append(datetime.fromtimestamp(int(timestamp)).strftime("%d/%m/%Y %H:%M:%S"))
     newItems.append(get_ip_addr_without_mask(int(Items[1])))
     newItems.append(get_ip_addr_without_mask(int(Items[2])))
     newItems.append(get_port_logs(Items[3]))
     newItems.append(get_port_logs(Items[4]))
     newItems.append(rProtocols[Items[5]])
     newItems.append(rActions[Items[6]])
     Reason = Items[7]
     if int(Reason) in Reasons.keys():
      Reason = Reasons[int(Reason)]
     newItems.append(Reason)
     newItems.append(Items[8])
     log_lines.append((timestamp,newItems))
     line = logs_module.readline()
     line = line.replace("\n","")
   
   log_lines = sorted(log_lines, key=lambda x: x[0])
   Logs = "\n".join(["{:<22} {:<15} {:<15} {:<10} {:<10} {:<8} {:<7} {:<20} {}".format(*S[1]) for S in log_lines])
   print "{:<22} {:<15} {:<15} {:<10} {:<10} {:<8} {:<7} {:<20} {}".format("Timestamp","src_ip","dst_ip","src_port","dst_port","protocol","action","reason","count")
   print Logs


 elif (sys.argv[1] == "clear_log"):
  with open("/sys/class/fw/log/reset", 'w') as reset_module:
   reset_module.write("0")

 else:
  print "Command does not exists!"
  return -1
 return 0

#log_device = open("/dev/fw_log", 'r')
#reset_device = open("/sys/class/fw/log/reset", 'w')
#rules_device = open("/sys/class/fw/rules/rules", 'w+')



if __name__ == "__main__":
 main()
