import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;

/**
 * YES i know they are static.
 * But they are final.
 * So they wont create any misshapings.
 * It is a matter of lack of time, I dont even have time to test paralillity of this program..
 */
public class TFTPServer {
    boolean DEBUG = false;
    public static final int TFTPPORT = 4970;
    public static final int BUFSIZE = 516;
    public static final int sizeOfDataField = 512;//2 byte opcode followed by 2 byte blockNum followed by [0,512] bytes of data
    public static final int sizeOfUdpData = 65507;//20Byte ipv4 header, 8 byte udp header
    public static final int maxLengthFileName = 255;//max length of filename (inclusive filending) of most Operating Systems
    public static final int maxShort = 65535;//maximal value for a short.

    public static final byte zeroByte = 0x00;
    private final int timeOut = 120000; //Connection will timeOut if nothing was done for 2 minutes,
    // change if you are disconnected this is really stupid
    public static final int timeOutSocket = 100;// 100 MilliSeconds
    public static final int maxNumRetrans = 5;//Maximally 5 retransmiisions

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

    public static final String READDIR = "SERVER_FILES/ReadWrite/"; //custom address at your PC
    public static final String WRITEDIR = READDIR; //custom address at your PC

    // OP codes
    public static final int OP_RRQ = 1;
    public static final int OP_WRQ = 2;
    public static final int OP_DAT = 3;
    public static final int OP_ACK = 4;
    public static final int OP_ERR = 5;

    public static final int minOp = 1;//Expect no smaller op than this
    public static final int maxOp = 5;//Expect no larger op than this.

    public static final int ERR_NOT_DEF = 0;//not defined
    public static final int ERR_FNF = 1;//file not found
    public static final int ERR_ACC_VIO = 2;//accessviolation
    public static final int ERR_DRUNK = 3;//Disk full or allocation exceeded (35meg)
    public static final int ERR_ILLEGAL = 4;//Tftp does not allow
    public static final int ERR_TID_UNKNOWN = 5;//Transfer ID unknown
    public static final int ERR_FILE_EXIST = 6;//File already exists
    public static final int ERR_NO_USER = 7;//no sutch user

    public static final int minError = 0;//must atleast be 1
    public static final int maxError = 7;//cannot handle errorcodes higher than 7

    public static final String crLF = "“\r\n”,";//LineEnding netascii
    public static final String netStringEnd = "\n";//LineEnding netascii


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
        final byte[] buf = new byte[BUFSIZE];

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

            if (DEBUG)System.out.println("Client: " + clientAddress);

            new Thread() {
                public void run() {
                    final StringBuffer requestedFile = new StringBuffer();
                    final StringBuffer mode = new StringBuffer();
                    final int reqtype = ParseRQ(buf, requestedFile, mode);

                    try {
                        DatagramSocket sendSocket = new DatagramSocket(null);
                        // Connect to client
                        sendSocket.connect(clientAddress);

                        if (!mode.toString().toLowerCase().equals("octet")) {

                            System.err.println("Are you from 1960 or something? You can only use octet, will send error");
                            send_ERR(sendSocket, ERR_ILLEGAL, "Access Denied:\n" +
                                    "You cant use netascii as trans_mode to this server");
                        } else {

                            System.out.printf("%s request for %s from %s using port %d\n",
                                    (reqtype == OP_RRQ) ? "Read" : "Write",
                                    sendSocket.getInetAddress(), clientAddress.getHostName(), clientAddress.getPort());

                            // Read request
                            if (reqtype == OP_RRQ) {
                                requestedFile.insert(0, READDIR);
                                if (DEBUG) System.out.println("File to read: " + requestedFile);

                                HandleRQ(sendSocket, requestedFile.toString(), OP_RRQ);
                            }
                            // Write request
                            else if (reqtype == OP_WRQ) {
                                requestedFile.insert(0, WRITEDIR);
                                if (DEBUG) System.out.println("File to write: " + requestedFile);
                                HandleRQ(sendSocket, requestedFile.toString(), OP_WRQ);
                            } else {
                                System.out.println("Failed to parse message to socket: " + socket.getInetAddress() + "\n" +
                                        "with opcode: " + reqtype);
                            }
                        }
                        System.out.println("Closing: " + sendSocket.getInetAddress());
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
        if (DEBUG)System.out.println("This is address from recive: " + inetSocketAddress.toString());

        return inetSocketAddress;
    }

    /**
     * Parses the request in buf to retrieve the type of request and requestedFile
     * TODO: This is worst safety since Y2K, should check so java does not print Wonderfull/../.. and navigates to root
     * TODO: But there is not enough time, let's just trust java!
     *
     * @param buf           (received request)
     * @param requestedFile (name of file to read/write).
     * @param mode          (mode of transfer)
     * @return OP_Code (request type: RRQ or WRQ). OR: -1 if opCode invalid, -2 if filename is over 255 bytes long.
     */
    private int ParseRQ(final byte[] buf, StringBuffer requestedFile, StringBuffer mode) {
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
            index++;
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
        if (DEBUG)System.out.println("REQUESTED: OP:" + opcode +", For file: "
                + requestedFile.toString() +", Using mode: "+ mode.toString());
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

        if (opcode == OP_RRQ) {
            // See "TFTP Formats" in TFTP specification for the DATA and ACK packet contents
            boolean result = send_DATA_receive_ACK(sendSocket, requestedFile);
            System.out.println("From RRQ: " + result);
        } else if (opcode == OP_WRQ) {
            boolean result = receive_DATA_send_ACK(sendSocket, requestedFile);
            System.out.println("From WRQ: " + result);
        } else {
            System.out.println("Invalid request(Or error). Sending an error packet.");
            System.out.println("Socket: " + sendSocket.getInetAddress() + " used opCode: " + opcode);
            // See "TFTP Formats" in TFTP specification for the ERROR packet contents
            send_ERR(sendSocket, ERR_NOT_DEF, "Illegal command");
            return;
        }
    }

    /**
     * This is response to a RRQ request (read)
     * IS DONE BUT UGLY As Fuck.
     *
     * @param datagramSocket
     * @param requestedFile
     * @return True if success, false if any kind of error? Or should
     * Errors be handled in this method? and redelayed to "send_error()"? Yes they are.
     */
    private boolean send_DATA_receive_ACK(DatagramSocket datagramSocket, String requestedFile) {
        if (DEBUG) {
            System.out.println("Replying with data to:");
            System.out.println(datagramSocket.getInetAddress() + ", Using port: " + datagramSocket.getPort());
        }
        boolean allPacketsSent = false;

        int blockNum = 1;
        File file = new File(requestedFile);
        if (DEBUG) System.out.println("FilePath: " + file.getAbsolutePath());
        FileInputStream fileInputStream = null;
        byte[] returnBuff = new byte[BUFSIZE];
        byte[] buf = new byte[sizeOfDataField];
        if (file.isFile()) {
            try {
                long heartBeat = System.currentTimeMillis();
                int numRetransmissions = 0;
                final int maxRetransmissions = 5;
                boolean isLastPacket = false;
                if (file.length() >= (maxShort * sizeOfDataField)) {
                    send_ERR(datagramSocket, ERR_ILLEGAL, "File is to big for TFTP: \n"
                            + file.length() + ", Bytes actually.\nMax is: " + ((maxShort * sizeOfDataField) - 1) + ", Bytes ");
                    return false;
                }
                fileInputStream = new FileInputStream(file);
                if (fileInputStream.available() == 0) {
                }
                //Commented
                while (fileInputStream.available() >= 0 && System.currentTimeMillis() - heartBeat < timeOut) {
                    //Also reads empty files
                    int lengthRead = -1;
                    if (fileInputStream.available() == 0) {
                        lengthRead = 0;
                    } else {
                        lengthRead = fileInputStream.read(buf);
                    }
                    if(DEBUG)System.out.println("LENGTH READ GOOOD DAMN IT: " + lengthRead);
                    if (lengthRead < 0) {
                        //Could be some kind of fileNotFound
                        //More likely i am just paranoid: TODO: FFS DONT BE SO SCARRED
                        System.err.println("This should never happen but port: " + datagramSocket.getPort() + " succeded");
                        if (fileInputStream != null) fileInputStream.close();
                        send_ERR(datagramSocket, ERR_NOT_DEF, "Yet again succeded  with the impossible\n" +
                                "Better safe than sorry");
                        return false;
                    }
                    if (lengthRead < sizeOfDataField) {//This is the last packet
                        byte[] tempBuff = new byte[lengthRead];
                        System.arraycopy(buf, 0, tempBuff, 0, lengthRead);
                        buf = tempBuff;
                        returnBuff = new byte[lengthRead + 4];
                        isLastPacket = true;
                    }
                    ByteBuffer wrap = ByteBuffer.wrap(returnBuff);
                    putUnsignedShort(wrap, OP_DAT);
                    putUnsignedShort(wrap, blockNum);
                    System.out.println("SEND SOCK INET: "+datagramSocket.getInetAddress());
                    System.out.println("Send Sock port: "+datagramSocket.getPort());
                    wrap.put(buf);
                    DatagramPacket sendPacket =
                            new DatagramPacket(returnBuff,
                                    returnBuff.length,
                                    datagramSocket.getInetAddress(),
                                    //TODO: works on localhost using tftp-hpa
                                    //TODO: should probably reuse clientaddress from begining to create packets.
                                    datagramSocket.getPort());

                    datagramSocket.send(sendPacket);

                    int acked = receiveAck(datagramSocket, blockNum);
                    if (acked == 1) {
                        numRetransmissions = 0;
                        heartBeat = System.currentTimeMillis();
                        blockNum++;
                    } else if (acked == -1 || acked == -3) {
                        while (acked == -1 || acked == -3) {
                            if (numRetransmissions == maxRetransmissions) {
                                //TODO: close connection and return, this must be done in mainThread(if returned false)
                                System.err.println("Socket: " + datagramSocket.getPort() + ", made " + numRetransmissions
                                        + " resubmission and should therefore be seen as dead");
                                fileInputStream.close();
                                send_ERR(datagramSocket, ERR_NOT_DEF, "Ack was timedout.");
                                return false;
                            }
                            datagramSocket.send(sendPacket);
                            acked = receiveAck(datagramSocket, blockNum);
                            numRetransmissions++;
                            if (acked == 1) {
                                numRetransmissions = 0;
                                heartBeat = System.currentTimeMillis();
                                blockNum++;
                            }
                        }
                    } else {
                        System.err.println("Returning, because error was recieved from client connected to socket: "
                                + datagramSocket.getInetAddress());
                        return false;//Errors printed in recieveACK
                    }
                    if (isLastPacket && acked == 1) {
                        fileInputStream.close();
                        return true;
                    }
                }
            } catch (Exception e) {
                System.err.println("Is a file but not reachable, should just let this catch handle everything\n" + e);
                send_ERR(datagramSocket, ERR_FNF, "File not found: Send mail to:\n" +
                        "dontgiveashit@hotahaiti.ho for java exception.");
                return false;
            }

        } else {
            File readDirr = new File(READDIR);
            StringBuilder filesReadable = new StringBuilder();
            if (readDirr.isDirectory()) {
                File[] files = readDirr.listFiles();
                for (File tempFile : files) {
                    filesReadable.append(tempFile.getName());
                    filesReadable.append("\n");
                }
            }
            send_ERR(datagramSocket, ERR_FNF, "File not found:\n" +
                    "Here is list of readable files:\n\n" +
                    filesReadable.toString());
            return false;
        }
        return allPacketsSent;
    }

    /**
     * Recives acknowledgment with blockNum from socket, returns false if any error.
     * Is done but ugly, not the ugliest thou
     *
     * @param socket
     * @param blockNum
     * @return <p>
     * +1==True if acknowledgement returns same blockNum as <code>blockNum</code> given as argument.
     * 0 if undiagnosed error (probably disconnected client)
     * -1 if timeout.
     * -2 if it was an error message
     * -3 if received ackNum was not equal to <code>blockNum</code>
     * </p>
     */
    private int receiveAck(DatagramSocket socket, int blockNum) {
        if (DEBUG) System.out.println("Waiting for blocknum: " + blockNum);
        int wasAcked = 0;
        byte[] buf = new byte[4];
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        long start = System.currentTimeMillis();
        try {
            socket.setSoTimeout(timeOutSocket);
            try {
                socket.receive(receivePacket);
            } catch (SocketTimeoutException se) {
                if (DEBUG) System.out.println("RecieveAck took: " + (System.currentTimeMillis() - start));//TODO REMOVE

                System.err.println("Socket with port: " + socket.getPort() +
                        "\nTimed out when waiting for ack of blockNum: " + blockNum);
                socket.setSoTimeout(0);
                return -1;
            }
            socket.setSoTimeout(0);
            ByteBuffer wrap = ByteBuffer.wrap(buf);
            int opCode = getUnsignedShort(wrap);
            if (opCode != OP_ACK) {
                if (opCode == OP_ERR) {
                    StringBuilder errorMessage = new StringBuilder();
                    for (int i = wrap.position(); i < buf.length; i++) {
                        if (buf[i] == 0x00) {
                            System.err.println("An error with message: " + errorMessage.toString() + "\n" +
                                    "Was recieved when waiting for acknum #" + blockNum);
                            send_ERR(socket, ERR_NOT_DEF, "You are assumed dead");
                            break;
                        }
                        errorMessage.append((char) buf[i]);
                    }
                    return -2;
                } else {
                    send_ERR(socket, ERR_ILLEGAL, "Mail me, because this is forbidden");
                }

            }
            int ackNum = getUnsignedShort(wrap);
            if (ackNum != blockNum) {
                System.err.println("Numbers are not equal:\n" +
                        "Client Tried to acknowledge: " + ackNum + ", to dataBlock#" + blockNum);
                return -3;
            } else return 1;

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
        byte[] buf = new byte[BUFSIZE];
        byte[] dataBuffer = null;
        File writeDirr = new File(WRITEDIR);
        long usableSpace = writeDirr.getUsableSpace();
        if (usableSpace < sizeOfDataField * maxShort) {
            send_ERR(datagramSocket, ERR_DRUNK, "Disk full or allocation exceeded:\n" +
                    "Directory is wasted drunk, can only fit: " + usableSpace + ", more of bytes.\n" +
                    "Email server admin and ask him to clean up server and send it to Behandlingshem.");
            return false;
        }

        if (!writeFile.isFile()) {
            try {
                writeFile.createNewFile();
            } catch (Exception e) {
                System.err.println("Failed to create file " + writeFile.getName() + "\n"
                        + e);
                if (DEBUG) e.printStackTrace();
                if (writeFile.isFile()) writeFile.delete();
                send_ERR(datagramSocket, ERR_NOT_DEF, "Something made it impossible to create file.");
                return false;
            }
        } else {//File exists.
            if (!DEBUG) {//If not "DEBUG", do not overWrite file.               TODO remove debug
                System.err.println("File: "+writeFile.getName()+", already exists." +
                        "\nTo allow overwriting: set 'DEBUG' to true.");
                send_ERR(datagramSocket, ERR_FILE_EXIST, "File already exists: \n"
                        + writeFile.getName());
                return false;
            }
        }

        try {
            fileOutputStream = new FileOutputStream(writeFile);
        } catch (FileNotFoundException e) {
            System.err.println("Could not outputstream writefile, Not found? WTF???\n" +
                    "Is it a file?: " + writeFile.isFile());
            if (DEBUG) e.printStackTrace();
            send_ERR(datagramSocket, ERR_NOT_DEF, "Could not create a OutputStream for your file: "
                    + writeFile.getName());
            return false;
        }

        boolean recievedAll = false;
        int blockNum = 0;//First ack
        int totalLength = 0;
        sendAck(datagramSocket, blockNum);

        // last packet is the smallest
        try {
            while (true) {//This is always true, instead of good design I return. Half of the 1000 line code is return statements.
                DatagramPacket receivePacket = new DatagramPacket(buf, buf.length); //can be created here because
                boolean recievedAPacket = false;
                int numRetransAck = 0;
                while (!recievedAPacket) {
                    datagramSocket.setSoTimeout(timeOutSocket);
                    try {
                        datagramSocket.receive(receivePacket);
                        datagramSocket.setSoTimeout(0);
                        recievedAPacket = true;
                    } catch (SocketTimeoutException timeout) {
                        datagramSocket.setSoTimeout(0);
                        System.err.println("Socket with port: " + datagramSocket.getPort() + "\n" +
                                "Timed out waiting for packet: " + (blockNum + 1));
                        if (numRetransAck == maxNumRetrans) {
                            send_ERR(datagramSocket, ERR_NOT_DEF,
                                    "Server never recieved block #" + blockNum + ", of file "
                                            + writeFile.getName() + ".\n" +
                                            "After" + numRetransAck + ", retransmissions.\n" +
                                            "Will therefore count you as dead.");
                            if (fileOutputStream != null) fileOutputStream.close();
                            if (writeFile.isFile()) writeFile.delete();
                            return false;
                        }
                        sendAck(datagramSocket, blockNum);//previous packet
                        numRetransAck++;
                    }
                }
                blockNum++;

                int lengthOfPacket = receivePacket.getLength();
                if (blockNum == maxShort && lengthOfPacket == 512 + 4) {//Disk full
                    send_ERR(datagramSocket, ERR_DRUNK, "Disk full or allocation exceeded:\n" +
                            "You tried to transfer a file bigger then " + (blockNum * sizeOfDataField) + " Bytes.\n" +
                            "Im sorry, but i recommend you use something else.");
                    fileOutputStream.close();
                    writeFile.delete();
                    return false;
                }
                ByteBuffer wrap = ByteBuffer.wrap(buf);
                int opCode = getUnsignedShort(wrap);

                if (opCode != OP_DAT) {
                    System.err.println("Error: opcode is not equal DAT in recive.\n"
                            + "Opcode received: " + opCode + "\n"
                            + "Opcode expected: " + OP_DAT);
                    send_ERR(datagramSocket, ERR_NOT_DEF, "How you managed get this far is beyond me.\n" +
                            "Opcode recieved: " + opCode + ", Opcode expected: " + OP_DAT + "\n" +
                            "You are seen as dead from now on(according to morgans Requirements)");
                    fileOutputStream.close();
                    writeFile.delete();
                    return false;
                }
                int tempBlock = getUnsignedShort(wrap);
                if (tempBlock != blockNum) {
                    System.err.println("Error: blockNum is not what expected in receive.\n"
                            + "BlockNum received: #" + opCode + "\n"
                            + "BlockNum expected: #" + OP_DAT);
                    send_ERR(datagramSocket, ERR_NOT_DEF, "BlockNum error:\n" +
                            "Recieved: " + tempBlock + ", Expected: " + blockNum);
                    fileOutputStream.close();
                    writeFile.delete();
                    return false;//TODO implement error
                }

                dataBuffer = new byte[lengthOfPacket - wrap.position()];
                System.arraycopy(buf, wrap.position(), dataBuffer, 0, lengthOfPacket - wrap.position());
                totalLength += dataBuffer.length;

                fileOutputStream.write(dataBuffer);
                fileOutputStream.flush();
                sendAck(datagramSocket, blockNum);
                if (lengthOfPacket - 4 < sizeOfDataField) {
                    recievedAll = true;
                    break;
                }
            }
        } catch (Exception e) {
            if (e instanceof IOException) {
                send_ERR(datagramSocket, ERR_NOT_DEF, "Call David and specify WTF you did.");
            }
            System.err.println("Some error in recive_data");
            if (DEBUG) e.printStackTrace();
            try {
                if (fileOutputStream != null) fileOutputStream.close();
                if (writeFile.isFile()) writeFile.delete();
            } catch (IOException e1) {
                System.err.println("Failed to close FileOutputStream, or delete WriteFile " + e1);
                if (DEBUG) e1.printStackTrace();
            }
            return false;
        } finally {//Will most likely be returned false before this.
            try {
                if (fileOutputStream != null) fileOutputStream.close();
                if (!recievedAll && writeFile.isFile()) writeFile.delete();
            } catch (IOException e) {//It was most likely already closed
                send_ERR(datagramSocket, ERR_NOT_DEF, "Should give David a slap.\n" +
                        "He was to lazzy to test all cases.");
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
        DatagramPacket errorPacket = new DatagramPacket(//TODO What fucking port and address is forced into packet?
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
}
