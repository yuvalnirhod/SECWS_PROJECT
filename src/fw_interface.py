#!/usr/bin/env python2
import sys
import os

def check_module_exists():
	bool rules_device = os.path.isfile("/sys/class/fw/rules/rules")
	bool log_device = os.path.isfile("/dev/fw_log")
	bool reset_device = os.path.isfile("/sys/class/fw/log/reset")
	return rules_device and log_device and reset_device


def main():

	if (sys.argv[1] == "load_rules"):
		if (len(sys.argv) == 3):
			if (os.path.isfile("/sys/class/fw/rules/rules") and is.path.isfile(sys.argv[2])):
				with open("/sys/class/fw/rules/rules", 'w') as rules_module:
					f = open(sys.argv[2], 'r')
					


	elif (sys.argv[1] == "show_rules"):


	elif (sys.argv[1] == "show_log"):

	
	elif (sys.argv[1] == "reset_log"):


	else:
		print "Command does not exists!"
		return -1
	if (!check_module_exists()):
		print "Module does not exists!"
		return -1;
 
	log_device = open("/dev/fw_log", 'r')
	reset_device = open("/sys/class/fw/log/reset", 'w')
	rules_device = open("/sys/class/fw/rules/rules", 'w+')



if __name__ == "__main__":
	main()
