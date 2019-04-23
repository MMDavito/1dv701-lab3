Port is 4970
localhost 4970

tftp localhost 4970 -c get readShit.MD

/home/david/Documents/shit.txt

1. implement recieveFrom





4.0 Check if acks get transmitted via server in virtualbox and wireshark annalysis.
5.0 Start making it threaded.


//TODO FFS I use external host addresses instead of servers to build DatagramPacket




DatagramSocket testSocket = new DatagramSocket(null);//TODO USE THIIS INSTEAD OF "Socket" to "test" timeout, against udpechoServer
            InetSocketAddress echoAddress = new InetSocketAddress("localhost", 4971);
            testSocket.connect(echoAddress);

try {
                testSocket.receive(receivePacket);//TODO must be "socket"
            } catch (SocketTimeoutException se) {
                System.err.println("Socket with port: " + socket.getPort() +
                        "\nTimed out when waiting for ack of blockNum: " + blockNum);
                socket.setSoTimeout(0);
                return false;
            }

---------------------------------
#Comments for resubmission:
https://askubuntu.com/questions/201505/how-do-i-install-and-run-a-tftp-server
service tftp
{
protocol        = udp
port            = 69
socket_type     = dgram
wait            = yes
user            = nobody
server          = /usr/sbin/in.tftpd
server_args     = /tftpboot
disable         = no
}

#----------------------------------
test_tftp.py::test_GMBFail1stAck
test_tftp.py::test_GMBFail2ndAck
################
Sen kan man också kolla att två clienter klarar av 
att köras samtidigt
Eller är det att de skall kunna connecta.
Att de kan svälta är inget problem?
Kolla varför följande är slow as fuck:
test_tftp.py::test_PMB1Blks PASSED
test_tftp.py::test_PMB3Blks PASSED
test_tftp.py::test_PMB512Blks PASSED

