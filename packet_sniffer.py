# Devon Maguire -- 109284550
# Guanming Lin -- 109299260
# Sung Jae Min -- 109602826

import socket, os, time, re
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
			file = open("parsed_file.txt")
			count = 0
			for line in file:
				count+=searchk(keyword,line)
			print("The keyword appears " + str(count) + " time(s) in the file")
		if command == 'searchr':
			regex = input("Please enter a regular expression to search with: ")
			file = open("parsed_file.txt")
			print("Results of Regex:")
			for line in file:
				searchr(regex,line)
		if command == 'exit':
			print("Goodbye")
			exit()
		if command == 'help':
			help()
		else:
			pass

def collect(run_time):
	host = socket.gethostbyname(socket.gethostname())  # get the host name for the computer

	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # create a socket that captures all ethernet frames

	file = open("dump_file.txt", 'wb+')  # create a new file to dump the bytes into

	start_time = time.time() # record the time the capturing begins

	while (time.time() - start_time) <= run_time:  # collect packets indefinitely
		#print(str(time.time() - start_time))
		packet, addr = sniffer.recvfrom(65565)
		file.write(packet)  # dump the parsed data into the dump file
		file.write(b'\t\x00\n\x00\n\t')

	#print("Finished capturing, now parsing packets...")
	file.close()
	inspector.parse()
	#print("Finished parsing packets.")

def searchk(keyword,sentence):
	s = sentence.split()
	count = 0
	for word in s:
		if keyword in word:
			count+=1
	return count

def searchr(regex,sentence):
	result = ""
	result = re.findall(r''+regex,sentence)
	if result == "":
		print("No matching strings found")
	elif not result:
		return
	else:
		print(result)
	return

def help():
	print("----Help Menu----")
	print("collect\t\tprompts for an amount of time (in seconds) and then collects packets for that duration")
	print("searchk\t\tprompts for a keyword to search for in the file, returns the number of times that keyword is found")
	print("searchr\t\tprompts for a regular expression and returns the strings that match that expression in the file")
	print("exit\t\texits the program")

if __name__ == '__main__':
	main()
