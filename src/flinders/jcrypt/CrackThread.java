package flinders.jcrypt;

import java.util.concurrent.CountDownLatch;

public class CrackThread implements Runnable {

    byte[] decryptedText = null;
    CountDownLatch latch;
    JCryptUtil.EncryptedData ciphertext;
    private int start, stop;
    private String chars =  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private String password = ""; 
    private static volatile boolean found = false;
    
     public CrackThread(int start, int stop, JCryptUtil.EncryptedData ciphertext, CountDownLatch latch) {
         this.start = start;
         this.stop = stop;
         this.ciphertext = ciphertext;
         this.latch = latch;
     }
    
    @Override
    public void run() {
      
        while(!found && !Thread.currentThread().isInterrupted()) {
            for(int i = start; i < stop; i++) {
                for(int j = 0; j < chars.length(); j++) {
                    for(int k = 0; k < chars.length(); k++) {
                        for(int l = 0; l < chars.length(); l++) {
                            for(int m = 0; m < chars.length(); m++) {
                                if(!found) {
                                    password = "c" + chars.charAt(i) + chars.charAt(j) + chars.charAt(k) + chars.charAt(l) + chars.charAt(m);
                                   // password = "cp3GR8";
                                    System.out.println("Trying: " + password);
                                    try { 
                                        decryptedText = JCryptUtil.decrypt(password, ciphertext);
                                        System.out.println("Found password: " + password);
                                        DecryptedText DT = new DecryptedText();
                                        DT.setDT(decryptedText);
                                        found = true;
                                    } catch (JCryptUtil.Problem ex) {

                                    }
                                } else {
                                    Thread.currentThread().interrupt();
                                }
                            }
                        }
                    }
                }
            }
        }
        latch.countDown();  
        
    } 
    
    
}

    

