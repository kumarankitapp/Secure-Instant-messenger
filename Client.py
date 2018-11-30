import socket
import sys
import threading


client_buff=4096
prompt=''


def client_send_message_thread():


        client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #registering client socket as datagram
        username_client= sys.argv[2]
        server_ip = sys.argv[4]
        server_port = int(sys.argv[6])
        server_address = server_ip,server_port

        while 1:

            prompt=raw_input('+>')


            if prompt.find('list') !=-1 and prompt.find('list')==0:# if list command is encountered

                message=username_client+','+'list'
                client_socket.sendto(message,(server_address))

                server_data1=str(client_socket.recvfrom(client_buff))
                server_data1=server_data1.split(',')[0]
                server_data1=server_data1[3:-1]


                print '<- Signed In Users: '+server_data1



            elif prompt.find('send')!=-1 and prompt.find('send')==0:  #if send command is encountered
                try:
                 get_client_details= prompt.split(' ')[1]+','+'send'
                 get_client_message= prompt.split(' ')[2:]



                 client_socket.sendto(get_client_details,(server_address))
                 client_socket.settimeout(5)


                 get_client_details= str(client_socket.recvfrom(client_buff)) #reusing variable for receiver details
                 client_socket.settimeout(None)

                 get_client_details=get_client_details.split(',')[0]
                 get_client_details=get_client_details[4:-1]
                 receiver_ip,receiver_port =str(get_client_details.split(':')[0]),int(get_client_details.split(':')[1])

                 final_message=''
                 for i in get_client_message:
                     final_message=final_message+str(i)+' '
                 construct_message=str(final_message.strip())
                 construct_message=construct_message+','+ username_client

                 receiver_addr=receiver_ip,receiver_port
                 client_socket.sendto(construct_message,receiver_addr)  #sending message to peer client
                 client_socket.settimeout(None)
                except:
                 print 'Wrong Username. Please check the username via list command and send the message in the format:'\
                       'send <username> <message>'

            else:
                print 'Commands Supported:\nlist - to get the complete list of users connected \n '\
                      'send <username> <message> - to send peers your message'






def main():
    if sys.argv[1]=='-u' and sys.argv[3]=='-sip' and sys.argv[5]=='-sp':
       try:
          username_client= sys.argv[2]
          server_ip = sys.argv[4]
          server_port = int(sys.argv[6])
       except:
          print 'Incorrect Input: Username, IP or Port not correct'
    else:
       print 'Usage: python client.py -u <username> -sip <server-ip> -sp <port>'


    try:
       client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
       client_name = socket.gethostname()
       client_ip = socket.gethostbyname(client_name)
    except:
       print 'Its not you, it\'s us, please try again'


    server_address = server_ip,server_port

    message=username_client+','+'SIGN-IN'   #sending SIGN-IN message to register user on the server
    client_socket.sendto(message,((server_address)))


    server_data=str(client_socket.recvfrom(client_buff))

    client_send_thread=threading.Thread(target=client_send_message_thread) #spawning a thread to send command
    client_send_thread.start()

    while 1:
            try:
                peer_message=str(client_socket.recvfrom(client_buff))

                peer_message_msg=peer_message.split(',')[0]
                peer_message_msg=peer_message_msg[2:]




                peer_message_username=peer_message.split(',')[1]
                peer_message_username=peer_message_username[:-1]


                peer_message_ip=peer_message.split(',')[2]
                peer_message_ip=peer_message_ip[3:-1]


                peer_message_port=peer_message.split(',')[3]
                peer_message_port=peer_message_port[1:-2]
                print '\n<-' + ' <From '+peer_message_ip+':'+peer_message_port+':'+peer_message_username+'>: '+peer_message_msg
                #final message to print
                sys.stdout.write('+>')
                sys.stdout.flush()
            except:
                continue # so that it goes on an endless listening loop



main()
