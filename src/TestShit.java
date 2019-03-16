import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class TestShit {
    public static void main(String[] args) {
        boolean areThey = areEqual();
        System.out.println("Are they equal: " + areThey);

    }

    private static boolean areEqual() {
        boolean areEqual = true;
        int sizeOfDataField = 512;
        int blockNum = 1;
        File originalFile = null;
        File writtenFile = null;
        try {
            originalFile = new File("CLIENT_FILES/read_to/512Chars.txt");
            writtenFile = new File("SERVER_FILES/read_files/512Chars.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }

        FileInputStream streamOrgi = null;
        FileInputStream streamWritten = null;
        byte[] buffOrgi = new byte[sizeOfDataField];
        byte[] buffWritten = new byte[sizeOfDataField];
        byte[] buf = new byte[sizeOfDataField];
        if (!(originalFile.isFile() && writtenFile.isFile())) {
            System.out.println("Not files");
            return false;
        } else if (originalFile.length() != writtenFile.length()) {
            System.out.println("Diff of length");
            System.out.println("Expected: " + originalFile.getName() + ", of length\n" + originalFile.length());
            System.out.println("Got:      " + writtenFile.getName() + ", of length\n" + writtenFile.length());


            return false;
        } else {
            long fileLength = originalFile.length();
            try {
                streamOrgi = new FileInputStream(originalFile);
                streamWritten = new FileInputStream(writtenFile);
                System.out.println("FileSize: " + fileLength + ", StreamSize: " + streamOrgi.available());
                if (streamOrgi.available() != streamWritten.available()) {
                    System.out.println("diffrent avalibility");
                    return false;
                }
                int available = streamOrgi.available();
                int section = 1;
                while (available - (sizeOfDataField * (section)) > 0) {
                    streamOrgi.read(buffOrgi);
                    streamWritten.read(buffWritten);
                    for (int i = 0; i < buffOrgi.length; i++) {
                        if (buffOrgi[i] != buffWritten[i]) {
                            System.out.println("They are not equal on index: " + ((available - (sizeOfDataField * (section)) + i)));
                        }
                    }
                    section++;
                }
                int length = available - (sizeOfDataField * (section - 1));//TODO FIX HERE
                if (length > 0) {
                    buffOrgi = new byte[length];
                    buffWritten = new byte[length];
                    streamOrgi.read(buffOrgi);
                    streamWritten.read(buffWritten);
                    for (int i = 0; i < buffOrgi.length; i++) {
                        if (buffOrgi[i] != buffWritten[i]) {
                            System.out.println("They are not equal on index: " + ((available - (sizeOfDataField * (section)) + i)));
                        }
                    }
                    section++;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return areEqual;
    }
}
