# Devon Maguire -- 109284550
# Guanming Lin -- 109299260
# Sung Jae Min -- ID #

import socket, os, time
import packet_inspector as inspector


def main():
	while True:
		command = input("\nPlease enter a command (or 'help' for a list of commands)\n")
		command.lower()
	
		if command == 'collect':
			run_time = input("Please enter an amount of time in seconds: ")
			collect(float(run_time))
		if command == 'searchk':
			keyword = input("Please enter a keyword to search for: ")
			#searchk(keyword)
		if command == 'searchr':
			regex = input("Please enter a regular expression to search with: ")
			#searchr(regex)
		if command == 'exit':
			print("Goodbye")
			exit()
		if command == 'help':
			help()
		else:
			help()

def collect(run_time):
	host = socket.gethostbyname(socket.gethostname())  # get the host name for the computer

	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # create a socket that captures all ethernet frames

	file = open("dump_file.txt", 'w+b')  # create a new file to dump the bytes into

	start_time = time.time() # record the time the capturing begins

	while (time.time() - start_time) <= run_time:  # collect packets indefinitely
		packet, addr = sniffer.recvfrom(65565)
		file.write(packet)  # dump the parsed data into the dump file
		file.write(b'\t\x00\n\x00\n\t')
		#print(packet)

	print("Finished capturing, now parsing packets...")
	file.close()
	inspector.parse()
	print("Finished parsing packets.")

def help():
	print("----Help Menu----")
	print("collect\t\tprompts for an amount of time (in seconds) and then collects packets for that duration")
	print("searchk\t\tprompts for a keyword to search for in the file, returns the number of times that keyword is found")
	print("searchr\t\tprompts for a regular expression and returns the strings that match that expression in the file")
	print("exit\t\texits the program")

if __name__ == '__main__':
	main()
