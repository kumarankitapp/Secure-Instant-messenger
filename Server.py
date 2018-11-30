import socket
import sys


client_list = {}
buff=4096

try:
      server_sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      host=socket.gethostname()
      host_ip=socket.gethostbyname(host)  #getting server host_ip for cross machine usage
except socket.error:
      print 'Something went wrong, please try again'
      sys.exit(1)


def server_setup(host_addr):
    server_sock.bind(host_addr)


def client_details(client_data): #passing all client data in the form username:message
    #print client_data
    client_port=client_data.split(',')[3]
    client_port=client_port[:-2]
    client_port=int(client_port.strip())

    client_ip=client_data.split(',')[2]
    client_ip=client_ip[2:]
    client_ip=client_ip[1:-1]
    client_ip=str(client_ip)

    username=client_data.split(',')[0]
    username=username[2:]
    username=username.strip()

    if client_data.find('SIGN-IN')!=-1:

        if client_list.has_key(username):
           server_sock.sendto("+> User already Signed In", ((client_ip,client_port)))

        else:
            client_list[username]=str(client_ip)+':'+str(client_port)
            server_sock.sendto('success',((client_ip),client_port))
        return

    elif client_data.find('list')!=-1:
        list_to_send = list(set(client_list.keys()) - set([username]))
        list_name=''
        for i in list_to_send[:]:
            list_name=list_name+' '+i

        server_sock.sendto(str(list_name),((client_ip),client_port))
        #print str(type(client_ip)) + str(type(client_port))
        return

    elif client_data.find('send')!=-1:
        try:
          user_info_to_send= client_list[username]
          server_sock.sendto("+>" + str(user_info_to_send), ((client_ip),client_port))
        except:
          server_sock.sendto("+> Username not present",((client_ip),client_port))

        return

def main():

    if len(sys.argv)==3 and sys.argv[1]== '-sp':
        print 'Server Initialized...'
    else:
        print 'Usage server.py -sp <port number>'
        sys.exit(1)

    try:
        port= int(sys.argv[2])
    except:
        print 'Please enter a valid port, Usage ChatServer.py -sp <port number>'



    host_addr=host_ip,port
    server_setup(host_addr)


    while 1:
              client_data = str(server_sock.recvfrom(buff))
              client_details(client_data)



main()
