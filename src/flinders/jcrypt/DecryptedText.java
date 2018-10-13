package flinders.jcrypt;

public class DecryptedText {
    public static byte[] decryptedText;
    
    public void setDT(byte[] p) {
        this.decryptedText = p;
    }
    
    public byte[] getDT() {
        return this.decryptedText;
    }
}
