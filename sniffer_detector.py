import os
import argparse
import subprocess
import psutil

POTENTIAL_NETWORK_PACKAGES = ['libpcap', 'libwireshark']

def print_process_info(pid):
	"""
	print_process_info(pid) --> None
	prints process information to screen
	"""

	p = psutil.Process(pid)
	print("{")
	print("\tNAME: {}\n\tPID: {}\n\tBIN: {}\n\tCWD: {}".format( p.name(),p.pid, 
		p.exe(), p.cwd()))
	for file in p.open_files():
		print("\tFile descriptor: {}".format(file.path))
	print("}")

def detect_by_raw_socket_usage():
	"""
	detect_by_raw_socket_usage() --> list
	Searching for open processes with open RAW sockets.
	"""

	lsof_output = subprocess.check_output("lsof -w | grep RAW | cut -d ' ' -f 4", shell=True)
	lsof_output = lsof_output.decode().split("\n")
	return lsof_output


def detect_by_library_usage():
	"""
	detect_by_library_usage() --> list
	Searching for processes with known sniffing libraries loaded.
	"""

	_pids = []
	for network_lib in POTENTIAL_NETWORK_PACKAGES:
		lsof_output = subprocess.check_output("lsof -w | grep {} | cut -d ' ' -f 4".format(network_lib), shell=True)
		_pids += lsof_output.decode().split("\n")
	return list(set(_pids))

def run(library, raw):

	_pids = []

	# Method 1 - check for RAW socket usage
	if raw:
		print("[*] Searching processes with open RAW sockets")
		_pids += detect_by_raw_socket_usage()	


	# Method 2 - check for potential sniffing libraries
	if library:
		print("[*] Searching processes that are using network sniffing libraries")
		_pids += detect_by_library_usage()

	# Remove duplicates
	_pids = set(_pids)
	if _pids:
		_pids.remove("")
	print("[*] {} processes were detected".format(len(_pids)))
	for _pid in _pids:
		print_process_info(int(_pid))

def main():
	arg_parse = argparse.ArgumentParser()
	arg_parse.add_argument("-l", "--library", help="find processes that load network sniffing packages", 
		action="store_true")
	arg_parse.add_argument("-r", "--raw", help="find processes open raw sockets", action="store_true")
	args = arg_parse.parse_args()
	run(args.library, args.raw)


if __name__ == "__main__":
	main()