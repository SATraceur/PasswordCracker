package flinders.jcrypt;

import jargs.gnu.CmdLineParser;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Static methods for encrypting/decrypting/reading/writing files and
 * interpreting command-line options correctly in this context.
 *
 * @author Martin Luerssen
 */
public class JCryptUtil {

    /**
     * Decrypt a block of data. Note: will throw a Problem exception if the
     * decryption failed (possibly due to an invalid passord).
     *
     * @param password with which the ciphertext is encrypted
     * @param ciphertext object containing the encrypted data
     * @return decrypted cleartext as an array of bytes
     */
    protected static byte[] decrypt(String password, EncryptedData ciphertext) throws Problem {
        
        Cipher cipher = makeCipher(password, Cipher.DECRYPT_MODE);
        byte[] decryptedData;
        
        try {
            
            decryptedData = cipher.doFinal(ciphertext.content);
        } catch (Exception e) {
            throw new Problem("Decryption failed ");
        }
        
        CRC32 crc = new CRC32();
        crc.update(decryptedData, 0, decryptedData.length);
        if (crc.getValue() != ciphertext.checksum) {
            throw new Problem("Checksum (" + ciphertext.checksum + ") invalid ");
        }
        
        return decryptedData;
    }

    /**
     * Encrypt a block of data.
     *
     * @param password with which the cleartext is to be encrypted
     * @param cleartext original unencrypted source data
     * @return object containing the data in encrypted form
     */
    protected static EncryptedData encrypt(String password, byte[] cleartext) throws Problem {
        Cipher cipher = makeCipher(password, Cipher.ENCRYPT_MODE);
        EncryptedData data = new EncryptedData();
        CRC32 crc = new CRC32();
        crc.update(cleartext, 0, cleartext.length);
        data.checksum = crc.getValue();
        try {
            data.content = cipher.doFinal(cleartext);
        } catch (Exception e) {
            throw new Problem("Encryption failed");
        }
        return data;
    }

    /**
     * Generate a cipher from the specified password.
     *
     * @param password with which to encrypt
     * @param opmode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE expected
     * @return Cipher object to use for encryption/decryption
     */
    private static Cipher makeCipher(String password, int opmode) throws Problem {
        char[] sharedKey = password.toCharArray();
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(new byte[]{
            (byte) 0x37, (byte) 0x73, (byte) 0xf1, (byte) 0x2b,
            (byte) 0xff, (byte) 0x98, (byte) 0xd5, (byte) 0xa9}, 20);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(sharedKey);
        SecretKey pbeKey;
        try {
            pbeKey = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(pbeKeySpec);
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(opmode, pbeKey, pbeParamSpec);
            return cipher;
        } catch (Exception e) {
            throw new Problem("Bad password");
        }
    }

    /**
     * Parse command-line options for encrypting/decrypting files.
     *
     * @param args command-line arguments
     * @return a set of encryption/decryption options
     */
    protected static Options parseOptions(String[] args) {
        Options opts = new Options();

        CmdLineParser parser = new CmdLineParser();
        CmdLineParser.Option cmdCrack = parser.addBooleanOption('c', "crack");
        CmdLineParser.Option cmdSave = parser.addBooleanOption('s', "save");
        CmdLineParser.Option cmdDecrypt = parser.addStringOption('d', "decrypt");
        CmdLineParser.Option cmdEncrypt = parser.addStringOption('e', "encrypt");
        CmdLineParser.Option cmdThreads = parser.addIntegerOption('t', "threads");

        try {
            parser.parse(args);
        } catch (CmdLineParser.OptionException e) {
            System.err.println("ERROR: " + e.getMessage());
            printUsage();
            System.exit(1);
        }

        opts.crack = (Boolean) parser.getOptionValue(cmdCrack, false);
        opts.saveToFile = (Boolean) parser.getOptionValue(cmdSave, false);
        opts.decryptionPassword = (String) parser.getOptionValue(cmdDecrypt, "");
        opts.encryptionPassword = (String) parser.getOptionValue(cmdEncrypt, "");
        opts.threads = (Integer) parser.getOptionValue(cmdThreads, 0);
        opts.filenames = parser.getRemainingArgs();

        if (opts.filenames.length == 0) {
            System.err.println("ERROR: No files specified");
            printUsage();
            System.exit(2);
        }

        return opts;
    }

    /**
     * Print the expected command-line usage of JCrypt to standard err.
     */
    protected static void printUsage() {
        System.err.println("USAGE: JCrypt -[c|[d|e password]] [-s] [-t number] files");
        System.err.println("where options include:");
        System.err.println("       -c decrypt files by guessing the password");
        System.err.println("       -d <password> decrypt files with the provided password");
        System.err.println("       -e <password> encrypt files with the provided password");
        System.err.println("       -s save output to file (instead of stdout)");
        System.err.println("       -t <number> number of threads to use");
    }

    /**
     * Read a file into a byte array.
     *
     * @param filename of file to read
     * @return data contained in file
     */
    protected static byte[] readRawFile(String filename) throws Problem {
        File file = new File(filename);
        InputStream in;
        try {
            in = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new Problem("File \"" + filename + "\" not found");
        }
        byte[] buf = new byte[(int) file.length()];
        int read = 0;
        while (read < buf.length) {
            int result;
            try {
                result = in.read(buf, read, buf.length - read);
            } catch (IOException e) {
                throw new Problem("Cannot read from file \"" + filename + "\"");
            }
            if (result == -1) {
                break;
            }
            read += result;
        }
        try {
            in.close();
        } catch (IOException e) {
        }
        return buf;
    }

    /**
     * Read a file encrypted with JCrypt.
     *
     * @param filename of file to read
     * @return an EncryptedData object with the encrypted data and a checksum to
     * verify validity after decryption
     */
    protected static EncryptedData readEncryptedFile(String filename) throws Problem {
        File file = new File(filename);
        EncryptedData data = new EncryptedData();
        InputStream in;
        try {
            in = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            throw new Problem("File \"" + filename + "\" not found");
        }
        byte[] checksum = new byte[8];
        data.content = new byte[(int) file.length() - 8];
        int read = 0;
        while (read < file.length()) {
            int result;
            try {
                if (read < 8) {
                    checksum[read] = (byte) (result = in.read());
                    result = (result < 0) ? -1 : 1;
                } else {
                    result = in.read(data.content, read - 8, (int) file.length() - read);
                }
            } catch (IOException e) {
                throw new Problem("Cannot read from file \"" + filename + "\"");
            }
            if (result == -1) {
                break;
            }

            read += result;
        }
        try {
            in.close();
        } catch (IOException e) {
        }
        data.checksum = ByteBuffer.allocate(8).put(checksum).getLong(0);
        return data;
    }

    /**
     * Write a byte array into a file.
     *
     * @param buffer to write to file
     * @param filename of file to write
     */
    protected static void writeRawFile(byte[] buffer, String filename) throws Problem {
        try {
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(buffer);
            fos.close();
        } catch (IOException e) {
            throw new Problem("Cannot write to file \"" + filename + "\"");
        }
    }

    /**
     * Write encrypted data into a file that can be read by readEncryptedFile.
     *
     * @param data to write to file
     * @param filename of file to write
     */
    protected static void writeEncryptedFile(EncryptedData data, String filename) throws Problem {
        try {
            FileOutputStream fos = new FileOutputStream(filename);
            //System.out.println(data.checksum);
            //byte[] chbuf = ByteBuffer.allocate(8).putLong(data.checksum).array();
            //System.out.println(ByteBuffer.allocate(8).put(chbuf).getLong(0));
            fos.write(ByteBuffer.allocate(8).putLong(data.checksum).array());
            fos.write(data.content);
            fos.close();
        } catch (IOException e) {
            throw new Problem("Cannot write to file \"" + filename + "\"");
        }
    }

    /**
     * Object containing data (assumed to be encrypted) and a checksum (assumed
     * to be of the decrypted data, to verify validity).
     */
    protected static class EncryptedData {

        public long checksum;
        public byte[] content;
    }

    /**
     * Object containing parsed command-line options as relevant to JCrypt.
     */
    protected static class Options {

        public boolean crack = false;
        public boolean saveToFile = false;
        public String decryptionPassword = "";
        public String encryptionPassword = "";
        public int threads = 0;
        public String[] filenames = new String[0];
    }

    /**
     * An exception thrown by a JCrypt method.
     */
    @SuppressWarnings("serial")
    protected static class Problem extends Exception {

        public Problem(String reason) {
            super(reason);
        }
    }

}
