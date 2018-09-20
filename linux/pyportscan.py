import sys
import os
import httplib
import socket
from threading import Thread
from time import sleep

opened_ports = []
m_ports = []
m_curr_row = 0
m_total_rows = 0
m_host = ''
m_threads = []
m_no_threads = 0

def usage():
        print('\n\t:: [PH] Index Python Port Scanner ::')
	print('\t    http://www.asianzines.blogspot.com ')
        print('Usage:')
        print('python pyportscan.py -t [HOST] -r <port #> <max port #>')
	print('python pyportscan.py -t [HOST] -s <ports separated by comma>')
        print('   -t = The target site or host address')
        print('   -r = Range port number from minimum to maximum')
        print('Example: \n$ python pyportscan.py -t targetsite.com -r 22 5132\n')
	print('Example: \n$ python pyportscan.py -t targetsite.com -s 22,80,3306,3389,8080,5932\n')
        return


def is_online(host):
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return False
    else:
        return True 
	
def validate_input(host, min_port, max_port, is_specified = False):
	if not is_online(host):
		print 'Server/Host: %s is not up!' %(host) 
		return False
	if is_specified: 
		ports = get_selected_ports(min_port)
		for p in ports:
			if not p.isdigit():
				print 'Please enter numeric value for ports'
				break
			elif p < 0:
				print 'Ports must not contain negative values'
				break
	else:
		if not min_port.isdigit() and not max_port.isdigit():	
    			print 'Please enter numeric value for ports' 
			return False                                     	
		if min_port < 0 or max_port < 0:
			print 'Ports must not contain negative values' 
			return False
		if min_port > max_port:
			print 'Min port %d is greater than maximum port %d' %(min_port, max_port) 
			return False

	return True

def clearscreen():
	os.system('cls' if os.name == 'nt' else 'clear')

def get_selected_ports(raw_ports):
	ports = []
	ports.extend(raw_ports.split(','))
	return ports


def scan_port(port):
	global m_host
	try:
			port = int(port)
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(2)
			result = sock.connect_ex((m_host, port))
			if result == 0:
				print '%d' %(port)
				opened_ports.append(port)
			sock.close()
	except KeyboardInterrupt:
    		print 'You pressed Ctrl+C'
	except socket.gaierror:
    		print 'Hostname could not be resolved'
	except socket.error:
    		print 'Could not connect to the server'

def get_port():
     global m_curr_row, m_total_rows
     global m_ports
     if m_curr_row > m_total_rows: return None
     port = m_ports[m_curr_row]
     m_curr_row = m_curr_row + 1
     return str(port)

def run_scan():
     global m_curr_row,m_ports,m_host,m_total_rows,m_host
     u = get_port()
     while u != None:
        if len(u) > 0:
          t = Thread(target=scan_port, args=(u,))
          t.start()
 
          #clearscreen()
          #print 'Scanning %s:%s (%d/%d)' %(m_host, u, m_curr_row, m_total_rows + 1)
          while(t.isAlive()):
             sleep(0xA)
	u = get_port()

def start():
	global m_no_threads, m_threads
	for index in range(0, m_no_threads):
		m_threads.append(Thread(target=(run_scan)))
		m_threads[index].start()
		sleep(.02)
	while(check_running()):
		sleep(0xA)
	stop()

def check_running():
	global m_no_threads, m_threads
	for index in range(0, m_no_threads):
		if m_threads[index].isAlive():
			return True
	return False

def stop():
	global m_no_threads, m_threads
	for index in range(0,m_no_threads):
		m_threads[index]._Thread__stop() 

def main():
	if len(sys.argv) == 5 or len(sys.argv) == 6:
		mode = [sys.argv[1], sys.argv[3]]
		if len(sys.argv) == 5 and not mode[1] == '-s':
			usage()
			sys.exit(0)
		if len(sys.argv) == 6 and not mode[1] == '-r':
			usage()
			sys.exit(0)

		if mode[0] == '-t' and (mode[1] in('-r','-s')):
			global m_host
			m_host = str(sys.argv[2])
			min_port = sys.argv[4]
			max_port = sys.argv[5] if mode[1] == '-r' else ''
			is_specified = True if mode[1] == '-s' and len(sys.argv) == 5 else False
			
			if validate_input(m_host,min_port,max_port,is_specified):
				print '\n##### Started scanning host: %s #####\n' %(m_host)
				sleep(2)
				global m_ports, m_total_rows
				if is_specified:
					m_ports = get_selected_ports(min_port)
				else:
					for port in range(int(min_port), int(max_port) + 1):
						m_ports.append(port)

				m_total_rows = len(m_ports) - 1
				if len(m_ports) > 0:
					global m_no_threads
					m_no_threads = 500
					if m_no_threads > len(m_ports):
						m_no_threads = len(m_ports) - 1
					else:
						m_no_threads = 500

					print '\n-- List of opened ports for %s --\n' %(m_host)
					thread = Thread(target=start)		
					thread.start()
					thread.join()
					while(thread.isAlive()):
						sleep(0xA)

				#clearscreen()
				#if len(opened_ports) > 0:
					
					#for p in set(opened_ports): print '%d' %(p)

				print '\n##### Game Over #####\n\n'			
		else:
			usage()
	else:
		usage()


if __name__ == '__main__':
	main()