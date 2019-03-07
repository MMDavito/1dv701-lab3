
import java.net.DatagramSocket;

public class TFTP {
    final short maxBufSize = 512;

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

        public DATA() {
            throw new UnsupportedOperationException("Will fix all");
        }

        /**
         * @param data A datapacket for TFTP (bufsize must be <=512)
         * @return 1 if data set, -1 if data was already set (cannot override)
         */
        public int setData(byte[] data) {
            if (hasSent) {
                return -1;
            }
            if (data.length > maxBufSize) {
                return -2;
            } else {
                this.data = data;
                hasSent = false;
                return 1;
            }
        }

        public int sendData(DatagramSocket socket) {
            if (hasSent) {
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