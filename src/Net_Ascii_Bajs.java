import java.nio.charset.Charset;

public class Net_Ascii_Bajs {
    protected final Charset ascii = Charset.forName("US-ASCII");
    private String string;

    public Net_Ascii_Bajs(String stringToBajs) {
        byte[] bytes = stringToBajs.getBytes();
        byte[] tempelyBajs = new byte[bytes.length * 2];//For writing to
        int size = 0; //To use when one needs to concat array.
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == 0x00) {
                break;
            }
            if (bytes[i] < 0x20 || bytes[i] > 0x70) {
                //TODO IGNORE AND EDIT, or control controll characters, fuck
            }

            if (bytes[i] == 0x0A) {// it is lineFeed
                if (i > 0 && bytes[i - 1] != 0x0D) { //previous byte is not carrigereturn
                    //Seems to work, got no time to annalyse this shit SCII
                    //  throw new UnsupportedOperationException("Fuck yourself");
                }
            }
        }
        string = new String(stringToBajs.getBytes(), ascii);
    }

    public String getString() {
        return string;
    }
}
