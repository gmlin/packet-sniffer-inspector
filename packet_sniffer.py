# Devon Maguire -- 109284550
# Guanming Lin -- 109299260
# Sung Jae Min -- ID #

import socket, os


def main():
	# use the main function to call the other functions -- duh : P oh brother
	# anyway, if person types in "start" then start listening for packets
	# if person types in "stop" then stop listening
	# if person types in "help" then print a help menu
	running = True  # keep running on true until the user of the program wants to exit

	# ** PLEASE KEEP THIS COMMENT CODE FOR LATER **
	#	while running:
	#		command = print(input("Please enter a command or 'help' for more information\n"))
	#		command.lower()
	#
	#		if command == 'collect':
	#			time = input("Please enter an amount of time in seconds: ")

	# def collect(time):
	host = socket.gethostbyname(socket.gethostname())  # get the host name for the computer

	if os.name == 'nt':  # if the machine is a windows machine
		sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,
								socket.IPPROTO_IP)  # create a socket that accepts all TCP datagrams
		sniffer.bind((host, 0))  # bind the socket to the localhost
		sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # set the sniffer so it will keep the IP headers
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # for windows need to set to promiscuous mode
	else:
		sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # create a socket that captures all ipv4 packets
	# sniffer.bind((host,0)) # bind the socket to the localhost
	# sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # set the sniffer so it will keep the IP headers

	file = open("dump_file.txt", 'w+b')  # create a new file to dump the bytes into

	while True:  # collect packets indefinitely
		packet, addr = sniffer.recvfrom(65565)
		contents = parse(packet)  # parse the packet from the parsing function
		file.write(contents)  # dump the parsed data into the dump file
		file.write(b'\n')
		print(contents)
	# print("Recieved packet from " + addr[0]) # print out the ip address

	if os.name == 'nt':  # if the machine is a windows machine
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # turn off promiscuous mode


def parse(packet):
	return packet[14:-4]  # return the payload


# ***PLEASE KEEP THIS COMMENTED CODE FOR LATER***
# def help():
#	print("collect\t\tprompts for an amount of time and then collects packets for that duration\n")

if __name__ == '__main__':
	main()
