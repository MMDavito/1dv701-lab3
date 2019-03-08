import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;

public class TFTPServer {
    boolean DEBUG = true;
    public static final int TFTPPORT = 4970;
    public static final int BUFSIZE = 516;
    public static final int sizeOfDataField = 512;//2 byte opcode followed by 2 byte blockNum followed by [0,512] bytes of data
    private final int timeOut = 120000; //will timeOut after 2 minutes

    /*
    --------------------------------------------------------------
    Methods for unsigning stuffz
     */
    public static int getUnsignedShort(ByteBuffer bb) {
        return (bb.getShort() & 0xffff);
    }

    public static void putUnsignedShort(ByteBuffer bb, int value) {
        bb.putShort((short) (value & 0xffff));
    }


//------------------------------------------------------------------

    public static final String READDIR = "~/TEMP_LNU/read/"; //custom address at your PC
    public static final String WRITEDIR = "~/TEMP_LNU/write/"; //custom address at your PC
    // OP codes
    public static final int OP_RRQ = 1;
    public static final int OP_WRQ = 2;
    public static final int OP_DAT = 3;
    public static final int OP_ACK = 4;
    public static final int OP_ERR = 5;

    public static void main(String[] args) {
        if (args.length > 0) {
            System.err.printf("usage: java %s\n", TFTPServer.class.getCanonicalName());
            System.exit(1);
        }
        //Starting the server
        try {
            TFTPServer server = new TFTPServer();
            server.start();
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    private void start() throws SocketException {
        byte[] buf = new byte[BUFSIZE];

        // Create socket
        DatagramSocket socket = new DatagramSocket(null);

        // Create local bind point
        SocketAddress localBindPoint = new InetSocketAddress(TFTPPORT);
        socket.bind(localBindPoint);

        System.out.printf("Listening at port %d for new requests\n", TFTPPORT);

        // Loop to handle client requests
        while (true) {
            final InetSocketAddress clientAddress = receiveFrom(socket, buf);

            // If clientAddress is null, an error occurred in receiveFrom()
            if (clientAddress == null)
                continue;

            System.out.println("Client: " + clientAddress);

//TODO, Thread it from here. BUT first, make it work with one client.

            final StringBuffer requestedFile = new StringBuffer();
            final int reqtype = ParseRQ(buf, requestedFile);
//TODO WTF There is a thread here already?
            new Thread() {
                public void run() {
                    try {
                        DatagramSocket sendSocket = new DatagramSocket(0);

                        // Connect to client
                        sendSocket.connect(clientAddress);

                        System.out.printf("%s request for %s from %s using port %d\n",
                                (reqtype == OP_RRQ) ? "Read" : "Write",
                                sendSocket.getInetAddress(), clientAddress.getHostName(), clientAddress.getPort());

                        // Read request
                        if (reqtype == OP_RRQ) {
                            requestedFile.insert(0, READDIR);
                            HandleRQ(sendSocket, requestedFile.toString(), OP_RRQ);
                        }
                        // Write request
                        else {
                            requestedFile.insert(0, WRITEDIR);
                            HandleRQ(sendSocket, requestedFile.toString(), OP_WRQ);
                        }
                        sendSocket.close();
                    } catch (SocketException e) {
                        e.printStackTrace();
                    }
                }
            }.start();
        }
    }

    /**
     * Reads the first block of data, i.e., the request for an action (read or write).
     *
     * @param socket (socket to read from)
     * @param buf    (where to store the read data)
     * @return socketAddress (the socket address of the client)
     */
    private InetSocketAddress receiveFrom(DatagramSocket socket, byte[] buf) {
        // Create datagram packet
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        // Receive packet
        try {
            socket.receive(receivePacket);
        } catch (IOException e) {
            System.err.println("Error in receiving packet from socket with port: " + socket.getPort() + "\n" + e);
        }
        // Get client address and port from the packet
        InetSocketAddress inetSocketAddress = new InetSocketAddress(receivePacket.getAddress(), receivePacket.getPort());
        System.out.println("This is address from recive: " + inetSocketAddress.toString());

        return inetSocketAddress;
    }

    /**
     * Parses the request in buf to retrieve the type of request and requestedFile
     *
     * @param buf           (received request)
     * @param requestedFile (name of file to read/write)
     * @return opcode (request type: RRQ or WRQ)
     */
    private short ParseRQ(byte[] buf, StringBuffer requestedFile) {
        // See "TFTP Formats" in TFTP specification for the RRQ/WRQ request contents
        ByteBuffer wrap = ByteBuffer.wrap(buf);
        short opcode = wrap.getShort();
        return opcode;
    }

    /**
     * Handles RRQ and WRQ requests
     *
     * @param sendSocket    (socket used to send/receive packets)
     * @param requestedFile (name of file to read/write)
     * @param opcode        (RRQ or WRQ)
     */
    private void HandleRQ(DatagramSocket sendSocket, String requestedFile, int opcode) {
        System.out.println("Handeling here");

        if (opcode == OP_RRQ) {
            // See "TFTP Formats" in TFTP specification for the DATA and ACK packet contents
            boolean result = send_DATA_receive_ACK(sendSocket, requestedFile);
        } else if (opcode == OP_WRQ) {
            boolean result = receive_DATA_send_ACK(sendSocket, requestedFile, OP_ACK);
        } else {
            System.err.println("Invalid request. Sending an error packet.");
            // See "TFTP Formats" in TFTP specification for the ERROR packet contents
            send_ERR(sendSocket, requestedFile, OP_ERR);
            return;
        }
    }

    /**
     * TODO To be implemented
     */


    /**
     * This is response to a RRQ request (read)
     *
     * @param datagramSocket
     * @param requestedFile
     * @return
     */
    private boolean send_DATA_receive_ACK(DatagramSocket datagramSocket, String requestedFile) {
        System.out.println("Replying with data to:");
        System.out.println(datagramSocket.getInetAddress() + ", Using port: " + datagramSocket.getPort());
        boolean allPacketsSent = false;

        int blockNum = 1;
        File file = new File(requestedFile);
        FileInputStream fileInputStream = null;
        byte[] returnBuff = new byte[BUFSIZE];
        byte[] buf = new byte[sizeOfDataField];
        if (file.isFile()) {
            try {
                long heartBeat = System.currentTimeMillis();
                while (!allPacketsSent || (System.currentTimeMillis() - heartBeat) < timeOut) {

                    fileInputStream = new FileInputStream(file);
                    int fileLength = fileInputStream.available();
                    while (fileLength - (sizeOfDataField * blockNum) >= 0) {
                        fileInputStream.read(buf);
                        ByteBuffer wrap = ByteBuffer.wrap(returnBuff);
                        putUnsignedShort(wrap, OP_DAT);
                        putUnsignedShort(wrap, blockNum);
                        wrap.put(buf);
                        DatagramPacket sendPacket =
                                new DatagramPacket(returnBuff,
                                        returnBuff.length,
                                        datagramSocket.getInetAddress(),
                                        datagramSocket.getPort());

                        datagramSocket.send(sendPacket);
                        boolean acked = receiveAck(datagramSocket, blockNum);
                        if (acked) blockNum++;
                        else return false;
                    }
                    if (true || (fileLength - (sizeOfDataField * (blockNum - 1))) > 0) {//TODO: Should it always do this?, else remove "TRUE"||
                        //Send the last dataPacket with length <512
                        int length = fileLength - (sizeOfDataField * (blockNum - 1));
                        returnBuff = new byte[length + 4];
                        buf = new byte[length];
                        fileInputStream.read(buf);
                        ByteBuffer wrap = ByteBuffer.wrap(returnBuff);
                        putUnsignedShort(wrap, OP_DAT);
                        putUnsignedShort(wrap, blockNum);
                        wrap.put(buf);
                        DatagramPacket sendPacket =
                                new DatagramPacket(returnBuff,
                                        returnBuff.length,
                                        datagramSocket.getInetAddress(),
                                        datagramSocket.getPort());

                        datagramSocket.send(sendPacket);
                        boolean acked = receiveAck(datagramSocket, blockNum);
                        if (acked) {
                            allPacketsSent = true;
                        } else {
                            //TODO REMOVE????: throw new ConnectException("ERROR ON LAST PACKET");
                            return false;
                        }
                    }
                }
            } catch (Exception e) {//TODO; Resend a error package to socket (implement read first, then write, then errors)
                System.err.println("Is a file but not reachable, should just let this catch handle everything\n" + e);
            }

        } else {
            throw new UnsupportedOperationException("Need to implement this shit, probably return a error message and close connection");
        }


        return allPacketsSent;
    }

    private boolean receiveAck(DatagramSocket socket, int blockNum) {
        boolean wasAcked = false;
        byte[] buf = new byte[4];
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        try {
            socket.receive(receivePacket);

            ByteBuffer wrap = ByteBuffer.wrap(buf);
            int opCode = getUnsignedShort(wrap);
            int ackNum = getUnsignedShort(wrap);

            if (opCode != OP_ACK) {
                System.err.println("It is probably an error? " + opCode);
                return wasAcked;
            } else if (ackNum != blockNum) {
                System.err.println("Numbers are not equal:\n" +
                        "Tried to acknowledge: " + ackNum + ", to block#" + blockNum);
                return wasAcked;
            } else wasAcked = true;

        } catch (IOException e) {
            System.err.println("Error receiving acknowledgment: " + e);
            if (DEBUG) e.printStackTrace();
        }
        return wasAcked;
    }


    /**
     * This is response to a WRQ request (write)
     *
     * @param sendSocket
     * @param requestedFile
     * @param opcode
     * @return
     */
    private boolean receive_DATA_send_ACK(DatagramSocket sendSocket, String requestedFile, int opcode) {
        return true;
    }

    private void send_ERR(DatagramSocket sendSocket, String requestedFile, int opcode) {
    }

}



