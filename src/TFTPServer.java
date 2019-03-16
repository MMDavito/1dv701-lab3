import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;

public class TFTPServer {
    boolean DEBUG = true;
    public static final int TFTPPORT = 4970;
    public static final int BUFSIZE = 516;
    public static final int sizeOfDataField = 512;//2 byte opcode followed by 2 byte blockNum followed by [0,512] bytes of data
    public static final int sizeOfUdpData = 65507;//20Byte ipv4 header, 8 byte udp header
    public static final int maxLengthFileName = 255;//max length of filename (inclusive filending) of most Operating Systems
    public static final int maxShort = 65535;//maximal value for a short.

    public static final byte zeroByte = 0x00;
    private final int timeOut = 120000; //will timeOut after 2 minutes, change if you are disconnected
    public static final int timeOutSocket = 3000;// 3 Seconds

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

    public static final String READDIR = "SERVER_FILES/read_files/"; //custom address at your PC
    //public static final String READDIR = "/home/david/TEMP_LNU/read/"; //custom address at your PC
    public static final String WRITEDIR = "SERVER_FILES/written_files/"; //custom address at your PC
    //public static final String WRITEDIR = "/home/david/TEMP_LNU/write/"; //custom address at your PC

    // OP codes
    public static final int OP_RRQ = 1;
    public static final int OP_WRQ = 2;
    public static final int OP_DAT = 3;
    public static final int OP_ACK = 4;
    public static final int OP_ERR = 5;

    public static final int minOp = 1;//Expect no smaller op than this
    public static final int maxOp = 5;//Expect no larger op than this.

    //TODO IMPLEMENT THIS
    public static final int ERR_NOT_DEF = 0;//not defined
    public static final int ERR_FNF = 1;//file not found
    public static final int ERR_ACC_VIO = 2;//accessviolation
    public static final int ERR_DRUNK = 3;//Disk full or allocation exceeded (35meg)
    public static final int ERR_ILLEGAL = 4;//Tftp does not allow
    public static final int ERR_TID_UNKNOWN = 5;//Transfer ID unknown
    public static final int ERR_BLOCK_CREATE = 6;//File already exists
    public static final int ERR_NO_USER = 7;//no sutch user

    public static final int minError = 0;//must atleast be 1
    public static final int maxError = 7;//cannot handle errorcodes higher than 7

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
//TODO THREAD IT BEFORE SUBMITT

//TODO WTF There is a thread here already?
            new Thread() {
                public void run() {
                    final StringBuffer requestedFile = new StringBuffer();
                    final StringBuffer mode = new StringBuffer();
                    final int reqtype = ParseRQ(buf, requestedFile, mode);
                    if (mode.toString().equals("netascii")) {

                        System.err.println("Are you from 1960 or something? You can only use octet, will send error");
                        throw new UnsupportedOperationException("Implement send_error in start"); //TODO SEND_ERROR UNSUPPORTED
                    }
                    try {
                        DatagramSocket sendSocket = new DatagramSocket(null);
                        // Connect to client
                        sendSocket.connect(clientAddress);

                        System.out.printf("%s request for %s from %s using port %d\n",
                                (reqtype == OP_RRQ) ? "Read" : "Write",
                                sendSocket.getInetAddress(), clientAddress.getHostName(), clientAddress.getPort());

                        // Read request
                        if (reqtype == OP_RRQ) {
                            requestedFile.insert(0, READDIR);
                            System.out.println("File to read: " + requestedFile);
                            //TODO Remove hardcoded
                            //HandleRQ(sendSocket, requestedFile.toString(), OP_RRQ);
                            HandleRQ(sendSocket, requestedFile.toString(), OP_RRQ);
                        }
                        // Write request
                        else {
                            requestedFile.insert(0, WRITEDIR);
                            System.out.println("File to write: " + requestedFile);
                            //TODO Remove hardcoded (was static filename)
                            //HandleRQ(sendSocket, requestedFile.toString(), OP_WRQ);
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
     * TODO: extract filename from this buf to stringbuffer!
     *
     * @param buf           (received request)
     * @param requestedFile (name of file to read/write).
     * @param mode          (mode of transfer)
     * @return OP_Code (request type: RRQ or WRQ). OR: -1 if opCode invalid, -2 if filename is over 255 bytes long.
     */
    private int ParseRQ(byte[] buf, StringBuffer requestedFile, StringBuffer mode) {
        // See "TFTP Formats" in TFTP specification for the RRQ/WRQ request contents
        ByteBuffer wrap = ByteBuffer.wrap(buf);
        int opcode = wrap.getShort();
        if (opcode < minOp || opcode > maxOp) {
            return -1;
        }
        int index = wrap.position();
        int lengthName = 0;
        while (index < buf.length) {
            if (buf[index] == 0x00) {
                lengthName = index - wrap.position();
                break;
            } else if (lengthName == maxLengthFileName + 1) {
                return -2;
            } else {
                requestedFile.append((char) buf[index]);
            }
            index++;//TODO: Could FUBAR filename (see if wrap.position is culprit)
        }
        if (buf[index] == 0x00) {//End of filename, start of mode
            index++;
            while (index < buf.length) {
                if (buf[index] == 0x00) {
                    break;
                } else {
                    mode.append((char) buf[index]);
                }
                index++;
            }
        }
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
            System.out.println("From RRQ: " + result);
        } else if (opcode == OP_WRQ) {
            boolean result = receive_DATA_send_ACK(sendSocket, requestedFile);
            System.out.println("From WRQ: " + result);
        } else {
            System.err.println("Invalid request. Sending an error packet.");
            // See "TFTP Formats" in TFTP specification for the ERROR packet contents
            send_ERR(sendSocket, ERR_NOT_DEF, "Illegal command");
            return;
        }
    }

    /**
     * TODO To be implemented:
     * WRQ using implemented bellow
     *
     */


    /**
     * This is response to a RRQ request (read)
     * IS DONE BUT UGLY As Fuck.
     *
     * @param datagramSocket
     * @param requestedFile
     * @return True if success, false if any kind of error? Or should
     * Errors be handled in this method? and redelayed to "send_error()"?
     */
    private boolean send_DATA_receive_ACK(DatagramSocket datagramSocket, String requestedFile) {
        System.out.println("Replying with data to:");
        System.out.println(datagramSocket.getInetAddress() + ", Using port: " + datagramSocket.getPort());
        boolean allPacketsSent = false;

        int blockNum = 1;
        File file = new File(requestedFile);
        System.out.println("FilePath: " + file.getAbsolutePath());
        FileInputStream fileInputStream = null;
        byte[] returnBuff = new byte[BUFSIZE];
        byte[] buf = new byte[sizeOfDataField];
        if (file.isFile()) {
            try {
                long heartBeat = System.currentTimeMillis();
                int numRetransmissions = 0;
                final int maxRetransmissions = 5;
                boolean isLastPacket = false;
                if (file.length() >= (maxShort * sizeOfDataField)) {//TODO send_error
                    throw new UnsupportedOperationException("Need to resend error");
                }
                fileInputStream = new FileInputStream(file);
                if (fileInputStream.available() == 0) {
                }
                while (fileInputStream.available() >= 0 && System.currentTimeMillis() - heartBeat < timeOut) {
                    int lengthRead = -1;
                    if (fileInputStream.available() == 0) {
                        lengthRead = 0;
                    } else {
                        lengthRead = fileInputStream.read(buf);
                    }
                    if (lengthRead < 0) {
                        //TODO: this is also a fileNotFound
                        System.err.println("This should never happen but will close socket with port: " + datagramSocket.getPort());
                        datagramSocket.close();
                    }
                    if (lengthRead < sizeOfDataField) {
                        //This is the last packet
                        byte[] tempBuff = new byte[lengthRead];
                        System.arraycopy(buf, 0, tempBuff, 0, lengthRead);
                        buf = tempBuff;
                        returnBuff = new byte[lengthRead + 4];
                        isLastPacket = true;
                    }
                    ByteBuffer wrap = ByteBuffer.wrap(returnBuff);
                    putUnsignedShort(wrap, OP_DAT);
                    putUnsignedShort(wrap, blockNum);
                    wrap.put(buf);
                    DatagramPacket sendPacket =
                            new DatagramPacket(returnBuff,
                                    returnBuff.length,
                                    datagramSocket.getInetAddress(),
                                    datagramSocket.getPort());

                    //TODO REMOVE
                    System.out.println("Send packet before sending: " + sendPacket.getLength());
                    datagramSocket.send(sendPacket);
                    //TODO REMOVE
                    System.out.println("Send packet after sending: " + sendPacket.getLength());

                    boolean acked = receiveAck(datagramSocket, blockNum);
                    System.out.println("Was acked? " + (acked));
                    if (acked) {
                        numRetransmissions = 0;
                        heartBeat = System.currentTimeMillis();
                        blockNum++;
                        if (isLastPacket) {
                            fileInputStream.close();
                            return true;
                        }
                    } else {
                        while (acked == false) {
                            if (numRetransmissions == maxRetransmissions) {
                                //TODO: close connection and return, this must be done in mainThread(if returned false)
                                System.err.println("Socket: " + datagramSocket.getPort() + ", made " + numRetransmissions
                                        + " resubmission and should therefore be seen as dead");
                                fileInputStream.close();
                                return false;
                            }
                            System.out.println("Was not acked");
                            datagramSocket.send(sendPacket);
                            acked = receiveAck(datagramSocket, blockNum);
                            numRetransmissions++;
                        }
                    }
                }

            } catch (Exception e) {//TODO; Resend a error package to socket (implement read first, then write, then errors)
                System.err.println("Is a file but not reachable, should just let this catch handle everything\n" + e);
            }

        } else {
            throw new UnsupportedOperationException("Need to implement this shit, return error FNF");
        }


        return allPacketsSent;
    }

    /**
     * Recives acknowledgment with blockNum from socket, returns false if any error.
     * Is done but ugly, not the ugliest thou
     * TODO: Implement "Timeout" 10 sek är rimmligt
     *
     * @param socket
     * @param blockNum
     * @return True if acknowledgement returns same blockNum as <code>blockNum</code> given as argument.
     */
    private boolean receiveAck(DatagramSocket socket, int blockNum) {
        boolean wasAcked = false;
        byte[] buf = new byte[4];//TODO: UDP DATAGRAM SIZES 8 byte udpheader
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        try {
            long start = System.currentTimeMillis();
            socket.setSoTimeout(timeOutSocket);
            System.out.println("RecieveAck took: " + (System.currentTimeMillis() - start));
            try {
                socket.receive(receivePacket);
            } catch (SocketTimeoutException se) {
                System.err.println("Socket with port: " + socket.getPort() +
                        "\nTimed out when waiting for ack of blockNum: " + blockNum);
                socket.setSoTimeout(0);
                return false;
            }
            socket.setSoTimeout(0);
            byte[] tempArr = receivePacket.getData();
            System.out.println("Datasize of ack is: " + tempArr.length);
            InetAddress iDress = receivePacket.getAddress();
            System.out.println("Is this a address:" + iDress);
            System.out.println(tempArr.length);
            ByteBuffer wrap = ByteBuffer.wrap(buf);
            int opCode = getUnsignedShort(wrap);
            System.out.println("opcode from ack: " + opCode);
            int ackNum = getUnsignedShort(wrap);
            System.out.println("acknum from ack: " + ackNum);

            if (opCode != OP_ACK) {
                System.err.println("It is probably an error? " + opCode);
                return wasAcked;
            } else if (ackNum != blockNum) {
                System.err.println("Numbers are not equal:\n" +
                        "Client Tried to acknowledge: " + ackNum + ", to dataBlock#" + blockNum);
                return wasAcked;
            } else wasAcked = true;

        } catch (IOException e) {
            System.err.println("Error receiving acknowledgment: " + e);
            if (DEBUG) e.printStackTrace();
        }
        return wasAcked;
    }


    /**
     * This is "tested" using
     *
     * @param datagramSocket
     * @param requestedFile
     * @return
     */
    private boolean receive_DATA_send_ACK(DatagramSocket datagramSocket, String requestedFile) {
        File writeFile = new File(requestedFile);
        FileOutputStream fileOutputStream = null;
        byte[] buf = new byte[BUFSIZE];//TODO: Should it be size of data? and not entire message?
        byte[] dataBuffer = null;
        File writeDirr = new File(WRITEDIR);//TODO: COuld check if disk is not full!=!=!???

// SEND ACK OF WRQ? But first: extract info from packet!!!! TODO But fake, är tvärt om


        //   int blockID = 0;
        // sendAck(datagramSocket, blockID);
        System.out.println("Absolute path: " + writeFile.getAbsolutePath());
        //if (writeFile.isFile()){throw new UnsupportedOperationException("MUST IMPLEMENT send_error");}//TODO
        if (!writeFile.isFile()) {//TODO: reverse this functinality before submission.
            try {
                writeFile.createNewFile();//TODO: This should be norm, alternative.
                //TODO: "IF file.isfile() MUST return error code #6, file already exists
                //return false; TODO                ERR_ILLEGAL
            } catch (Exception e) {
                if (DEBUG) e.printStackTrace();
                System.out.println("PROBS ALREADY THERE " + e);
                if (DEBUG) e.printStackTrace();
                return false;//TODO throw error
            }
        }

        try {
            System.out.println("Is write a file? " + writeFile.isFile());
            fileOutputStream = new FileOutputStream(writeFile);
        } catch (FileNotFoundException e) {
            System.err.println("Could not outputstream writefile");
            if (DEBUG) e.printStackTrace();
            return false;//TODO: Must resend errors
        }

        boolean recievedAll = false;
        int blockNum = 0;//First ack
        sendAck(datagramSocket, blockNum); //TODO uncomment this code
        int totalLength = 0;

        // last packet is the smallest
        try {
            while (!recievedAll) {//TODO Count packets and if blocknum reaches max, return erro
                DatagramPacket receivePacket = new DatagramPacket(buf, buf.length); //can be created here because
                datagramSocket.receive(receivePacket);
                int lengthOfPacket = receivePacket.getLength();
                blockNum++;
                if (blockNum == maxShort) {
                    //TODO: Send_error
                    throw new UnsupportedOperationException("FIX THIS");
                }
                ByteBuffer wrap = ByteBuffer.wrap(buf);//TODO may cause error, and garbagecollector may be stupid.
                int opCode = getUnsignedShort(wrap);

                if (opCode != OP_DAT) {
                    System.err.println("Error: opcode is not equal DAT in recive.\n"
                            + "Opcode received: " + opCode + "\n"
                            + "Opcode expected: " + OP_DAT);
                    return false;//TODO implement error
                }
                int tempBlock = getUnsignedShort(wrap);
                if (tempBlock != blockNum) {
                    System.err.println("Error: blockNum is not what expected in receive.\n"
                            + "BlockNum received: #" + opCode + "\n"
                            + "BlockNum expected: #" + OP_DAT);
                    return false;//TODO implement error
                }

                dataBuffer = new byte[lengthOfPacket - wrap.position()];
                System.arraycopy(buf, wrap.position(), dataBuffer, 0, lengthOfPacket - wrap.position());

                totalLength += dataBuffer.length;
                System.out.println();
                System.out.println("BlockNum: " + blockNum);
                System.out.println("DataBuf length: " + dataBuffer.length);
                System.out.println("First element: " + (dataBuffer[0]));
                System.out.println("Last element: " + (dataBuffer[lengthOfPacket - 5]));

                fileOutputStream.write(dataBuffer);
                fileOutputStream.flush();
                sendAck(datagramSocket, blockNum);
                if (lengthOfPacket - 4 < sizeOfDataField) {//TODO Is not data but data+4

                    recievedAll = true;
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("Some error in recive_data");
            if (DEBUG) e.printStackTrace();
            try {
                fileOutputStream.close();
            } catch (IOException e1) {
                System.err.println("Failed to close FileOutputStream: " + e1);
                if (DEBUG) e1.printStackTrace();
                return false;//TODO RETURN ERROR (call method sendErro (send_error()))
            }
            return false;
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                System.err.println("Failed to close FileOutputStream before returning: " + e);
                if (DEBUG) e.printStackTrace();
            }
        }

        return recievedAll;
    }

    /**
     * To send acknowledgment of reciveing WRQ (block_id #0) or received data
     *
     * @param datagramSocket
     * @param blockNum
     */
    private void sendAck(DatagramSocket datagramSocket, int blockNum) {
        byte[] ackBuff = new byte[4];
        ByteBuffer wrap = ByteBuffer.wrap(ackBuff);
        putUnsignedShort(wrap, OP_ACK);
        putUnsignedShort(wrap, blockNum);

        DatagramPacket ackPacket =
                new DatagramPacket(ackBuff,
                        ackBuff.length,
                        datagramSocket.getInetAddress(),
                        datagramSocket.getPort());

        try {
            datagramSocket.send(ackPacket);
        } catch (IOException e) {
            System.err.println("Exception when trying to acknowledge blockNumber#" + blockNum + "");
            if (DEBUG) e.printStackTrace();
        }
    }

    /**
     * @param sendSocket  DatagramSocket to send error to.
     * @param errorCode   Integer specifying error code.
     * @param errorString String containing error message wiched to send. in netascii
     */
    private void send_ERR(DatagramSocket sendSocket, int errorCode, String errorString) {
        if (errorCode < minError || errorCode > maxError) {
            throw new UnsupportedOperationException("How did you program this server? This should not be possible." +
                    "\nThere exist no error code with value: " + errorCode);//Crashes server
        }

        if (errorString.length() > sizeOfUdpData - 5) {
            errorString = errorString.substring(0, sizeOfUdpData - 5);
        }
        Net_Ascii_Bajs netAscii = new Net_Ascii_Bajs(errorString);


        byte[] errorBuffer = new byte[sizeOfUdpData];
        ByteBuffer wrap = ByteBuffer.wrap(errorBuffer);
        putUnsignedShort(wrap, OP_ERR);
        putUnsignedShort(wrap, errorCode);
        byte[] fuckedByteArr = netAscii.getString().getBytes();
        wrap.put(fuckedByteArr);
        errorBuffer[errorBuffer.length - 1] = 0x00;//This to make sure in lazy way sure last byte is zero
        DatagramPacket errorPacket = new DatagramPacket(//TODO ERROR PRONE ON virtualbox will fail
                errorBuffer,
                errorBuffer.length,
                sendSocket.getInetAddress(),
                sendSocket.getPort());
        try {
            sendSocket.send(errorPacket);
        } catch (IOException e) {
            System.err.println("Exception when trying to send error to port: " + sendSocket.getPort());
            if (DEBUG) e.printStackTrace();
        }
    }

    //TODO REMOVE
    private static String byteArrToString(byte[] arr) {
        StringBuilder stringBuilder = new StringBuilder(arr.length);
        for (byte b : arr) {
            stringBuilder.append((char) b);
        }
        return stringBuilder.toString();
    }
}



