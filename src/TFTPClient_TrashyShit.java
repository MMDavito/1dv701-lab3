import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/**
 * I love trashy.
 * But this timemanagement is bizzare
 * <p>
 * This resends ack     if timeout of 10 milliseconds to next packet on get
 * Furthermore it sends error packet if 3 retrans of ack was made without next packet.
 * This resends data    if acknum was recieved twice
 * Sends error if 3 retrans where made without data i wished for.
 * <p>
 * <p>
 * NEXT::::
 * TODO: get that delays after second ack
 * TODO: put that delays 4 seconds after second block
 *
 * TODO: Will never work for the current settings of clientaddress och PISS
 * TODO: WAs so fucking trött att jag läste att opcode 4 var opcode för ERROR
 */
public class TFTPClient_TrashyShit {

    public static final String readFileName = "BULLSHIT_TESTDIRR_OF_TRASH/read_from/Happy_bee.jpg";
    public static final String writeToFileAbsPath = "BULLSHIT_TESTDIRR_OF_TRASH/write_to/Happy_bee_WRITTEN_Trash.jpg";
    public static final String readServerFileName = "Happy_bee.jpg";
    public static final String WRITEDIR = "BULLSHIT_TESTDIRR_OF_TRASH/write_to/";
    public static final String READDIR = "BULLSHIT_TESTDIRR_OF_TRASH/read_from/";

    public static final int sizeOfDataField = 512;//2 byte opcode followed by 2 byte blockNum followed by [0,512] bytes of data
    public static final int BUFSIZE = 516;//2 byte opcode followed by 2 byte blockNum followed by [0,512] bytes of data
    public static final int timeOutSocket = 10000;// 1 MilliSeconds
    public static final int retransAfter = 3;//retransmit after num of acks or blocks
    public static final int maxNumRetrans = 5;//Maximally 5 retransmiisions
    public static final int maxShort = 65535;//maximal value for a short.


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


    public static final int sizeOfUdpData = 65507;//20Byte ipv4 header, 8 byte udp header

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


    public static final boolean DEBUG = true;

    public static void main(String[] args) {
        System.out.println("Was recieved?? " + getFromServer());
    }


    private static boolean getFromServer() {
        boolean retBoo = false;

        DatagramSocket datagramSocket = null;
        try {
            datagramSocket = new DatagramSocket(null);
        } catch (SocketException e) {
            if (DEBUG) e.printStackTrace();
        }
        InetSocketAddress server = new InetSocketAddress("localhost", 4970);
        try {
            datagramSocket.connect(server);
            byte[] readReq = getCommand(readServerFileName);
            DatagramPacket reqPack = new DatagramPacket(
                    readReq,
                    readReq.length,
                    server.getAddress(),
                    server.getPort()
            );
            System.out.println(byteArrToString(readReq));
            datagramSocket.send(reqPack);
        } catch (Exception e) {
            if (DEBUG) e.printStackTrace();
        }


        File writeFile = new File(writeToFileAbsPath);


        FileOutputStream fileOutputStream = null;
        byte[] buf = new byte[BUFSIZE];
        byte[] dataBuffer = null;

        try {
            fileOutputStream = new FileOutputStream(writeFile);
        } catch (FileNotFoundException e) {
            System.err.println("Could not outputstream writefile, Not found? WTF???\n" +
                    "Is it a file?: " + writeFile.isFile());
            if (DEBUG) e.printStackTrace();
            return false;
        }

        boolean recievedAll = false;
        int totalLength = 0;



        // last packet is the smallest
        try {
            DatagramPacket receivePacket = new DatagramPacket(buf, buf.length); //can be created here because
            datagramSocket.receive(receivePacket);
            int blockNum = 0;
            boolean recievedAPacket = true;
            while (true) {//This is always true, instead of good design I return. Half of the 1000 line code is return statements.
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


    private static boolean putToServer() {
        boolean retBoo = false;
        try {
            DatagramSocket connectionSocket = new DatagramSocket(null);
            InetSocketAddress server = new InetSocketAddress("localhost", 4970);
            connectionSocket.connect(server);

        } catch (SocketException e) {
            if (DEBUG) e.printStackTrace();
        }
        return retBoo;
    }

    /**
     * To send acknowledgment of reciveing WRQ (block_id #0) or received data
     *
     * @param datagramSocket
     * @param blockNum
     */
    private static void sendAck(DatagramSocket datagramSocket, int blockNum) {
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
    private static void send_ERR(DatagramSocket sendSocket, int errorCode, String errorString) {
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

    /**
     * @param fileName
     * @return byteArr formated acording to TFTP RRQ
     */
    private static byte[] getCommand(String fileName) {
        final Charset ascii = Charset.forName("US-ASCII");


        byte[] fileNameArr = fileName.getBytes();
        int octetLength = "octet".getBytes().length;
        byte[] retArr = new byte[fileNameArr.length + 2 + 1 + "octet".length() + 1];
        ByteBuffer wrap = ByteBuffer.wrap(retArr);
        putUnsignedShort(wrap, OP_RRQ);
        int index = 0;
        for (int i = wrap.position(); i < fileNameArr.length + wrap.position(); i++) {
            retArr[i] = fileNameArr[i - wrap.position()];
            index = i;
        }
        index++;
        retArr[index] = 0x00;
        index++;
        fileNameArr = "octet".getBytes();
        for (int i = 0; i < fileNameArr.length; i++) {
            retArr[index + i] = fileNameArr[i];
        }
        index += fileNameArr.length;
        retArr[index] = 0x00;
        return retArr;
    }

    /**
     * @param fileName
     * @return byteArr formated acording to TFTP WRQ
     */
    private static byte[] putCommand(String fileName) {

        byte[] retArr = new byte[fileName.length() + 2 + 1 + "octet".length() + 1];
        ByteBuffer wrap = ByteBuffer.wrap(retArr);
        putUnsignedShort(wrap, OP_WRQ);
        byte[] fileNameArr = fileName.getBytes();
        int index = 0;
        for (int i = wrap.position(); i < fileNameArr.length + wrap.position(); i++) {
            retArr[i] = fileNameArr[i - wrap.position()];
            index = i;
        }
        index++;
        retArr[index] = 0x00;
        index++;
        fileNameArr = "octet".getBytes();
        for (int i = 0; i < fileNameArr.length; i++) {
            retArr[index + i] = fileNameArr[i];
        }
        index += fileNameArr.length;
        retArr[index] = 0x00;
        return retArr;
    }

    private static String byteArrToString(byte[] arr) {
        StringBuilder stringBuilder = new StringBuilder(arr.length);
        for (byte b : arr) {
            stringBuilder.append((char) b);
        }
        return stringBuilder.toString();
    }
}


