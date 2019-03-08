
import java.net.DatagramSocket;
import java.nio.ByteBuffer;

public class TFTP {
    final short BUFFSIZE = 512;

    /**
     * Read from server (so server sends data and recieves acknowledgments).
     */
    class RRQ {
        private final short opcode = 1;
        private String filename;//Is returned in a method bytes->charArr->String
        private final byte punctuation = 0;
        private String mode;//Is returned in a method bytes->charArr->String

        public RRQ() {
            throw new UnsupportedOperationException("Will fix all");
        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(opcode);
            stringBuilder.append(filename);
            stringBuilder.append(punctuation);
            stringBuilder.append(mode);
            stringBuilder.append(punctuation);
            return stringBuilder.toString();
        }

        public byte[] toByteArr() {
            byte[] buf = new byte[BUFFSIZE];
            ByteBuffer wrap = ByteBuffer.wrap(buf);
            wrap.putShort(1,(short) 3);
            System.out.println(opcode);
return null;
        }
    }

    class WRQ {
        private final short opcode = 2;
        private String filename;//Is returned in a method bytes->charArr->String
        private final byte punctuation = 0;
        private String mode;//Is returned in a method bytes->charArr->String

        public WRQ() {
            throw new UnsupportedOperationException("Will fix all");
        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(opcode);
            stringBuilder.append(filename);
            stringBuilder.append(punctuation);
            stringBuilder.append(mode);
            stringBuilder.append(punctuation);
            return stringBuilder.toString();
        }
    }

    class DATA {
        private final short opcode = 2;
        private int blockNum;
        private byte[] data;
        private boolean hasSent = false;
        private boolean hasData = false;

        public DATA() {
            throw new UnsupportedOperationException("Will fix all");
        }

        /**
         * @param data A datapacket for TFTP (bufsize must be <=512)
         * @return 1 if data set, -1 if data was already set (cannot override)
         */
        public int setData(byte[] data) {
            if (!hasSent) {
                return -1;
            }
            if (data.length > 516) {
                return -2;
            } else {
                this.data = data;
                hasSent = false;
                hasData = true;
                return 1;
            }
        }

        public int sendData(DatagramSocket socket) {
            if (hasSent || !hasData) {
                return -1;
            }

            return -666;
        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(opcode);
            return stringBuilder.toString();
        }
    }
}