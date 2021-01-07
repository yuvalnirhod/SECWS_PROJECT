#!/usr/bin/env python2
import sys
import os

Wrong_Format_MSG = "File in wrong format!"
Directions = ["in", "out", "any"]
Protocols = {"TCP":"6", "UDP":"17", "ICMP":"1", "any":"143"}
rProtocols = {"6":"TCP", "17":"UDP", "1":"ICMP", "143":"any"}
Actions = {"accept":"1","drop":"0"}
rActions = {"1":"accept","0":"drop"}
Ack = {"any":"3","yes":"2","no":"1"}
rAck = {"3":"any","2":"yes","1":"no"}


def check_module_exists():
 rules_device = os.path.isfile("/sys/class/fw/rules/rules")
 log_device = os.path.isfile("/dev/fw_log")
 reset_device = os.path.isfile("/sys/class/fw/log/reset")
 return rules_device and log_device and reset_device

def check_exists(path, mode):
 if (os.path.isfile(path)):
  return True
  print mode + " does not exists!"
 return False

def parse_ip_addr(addr):
 if (addr == "any"):
  return "0 0"

 ip, subnet_mask_size = addr.split("/")
 ip = ip.split(".")
 try:
  subnet_mask_size=int(subnet_mask_size)
 except:
  return False
 if (len(ip) != 4) or (subnet_mask_size > 32) or (subnet_mask_size < 0):
  print Wrong_Format_MSG
  return False

 ip_num = 0

 for i in range(len(ip)):
  try:
   ip_num = ip_num + int(ip[i])*(256**(len(ip)-i-1))
  except:
   print Wrong_Format_MSG
   return False

 return str(ip_num) + " " + str(subnet_mask_size)

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

def parse_port(port):
 if (port == ">1023"):
  return "1023"
 if (port == "any"):
  return "0"
 try:
  a = int(port)
 except:
  print Wrong_Format_MSG
  return False

 return port

def get_port(port):
 port = int(port)
 if (port == 1023):
  return ">1023"
 if (port == 0):
  return "any"
 return str(port)


def main():
 if (len(sys.argv)<2):
  print "Not enought arguments"
  return -1
 if (sys.argv[1] == "load_rules"):
  if (len(sys.argv) == 3):
   if (check_exists("/sys/class/fw/rules/rules", "Module") and check_exists(sys.argv[2], "Rules file")):
    Rules = ""
    f = open(sys.argv[2], 'r')
    line = f.readline()
    line = line.replace("\n","")
    while line:
     Items = line.split(" ")
     if (len(Items) != 9):
      print Wrong_Format_MSG + "1"
      return -1

     if (len(Items[0]) > 20):
      print Wrong_Format_MSG + "2"
      return -1

     if not (Items[1] in Directions):
      print Wrong_Format_MSG + "3"
      return -1
     Items[1] = str(Directions.index(Items[1]) + 1)

     Items[2] = parse_ip_addr(Items[2])
     if (not Items[2]):
      print Wrong_Format_MSG + "4"
      return -1

     Items[3] = parse_ip_addr(Items[3])
     if (not Items[3]):
      print Wrong_Format_MSG + "5"
      return -1


     if (not Items[4] in Protocols.keys()):
      print Wrong_Format_MSG + "6"
      return -1
     Items[4] = Protocols[Items[4]]

     Items[5] = parse_port(Items[5])
     if (not Items[5]):
      print Wrong_Format_MSG + "7"
      return -1

     Items[6] = parse_port(Items[6])
     if (not Items[6]):
      print Wrong_Format_MSG + "8"
      return -1

     if (Items[7] not in Ack.keys()):
      print Wrong_Format_MSG + "9"
      return -1
     Items[7] = Ack[Items[7]]

     if (Items[8] not in Actions.keys()):
      print Wrong_Format_MSG + "10"
      return -1
     Items[8] = Actions[Items[8]]

     Rules = Rules + " ".join(Items) + "\n"
     line = f.readline()
     line = line.replace("\n","")

    with open("/sys/class/fw/rules/rules", 'w') as rules_module:
     rules_module.write(Rules)
    f.close()


 elif (sys.argv[1] == "show_rules"):
  if (len(sys.argv) == 2):
   if check_exists("/sys/class/fw/rules/rules", "Module"):

    Rules = ""

    with open("/sys/class/fw/rules/rules", 'r') as rules_module:
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
      Rules = Rules + " ".join(newItems) + "\n"
      line = rules_module.readline()
      line = line.replace("\n","")

    print Rules[0:len(Rules)-1]

 elif (sys.argv[1] == "show_log"):
  pass

 elif (sys.argv[1] == "reset_log"):
  pass

 else:
  print "Command does not exists!"
  return -1
 return 0

#log_device = open("/dev/fw_log", 'r')
#reset_device = open("/sys/class/fw/log/reset", 'w')
#rules_device = open("/sys/class/fw/rules/rules", 'w+')



if __name__ == "__main__":
 main()
