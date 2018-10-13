package flinders.jcrypt;

import java.io.File;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JCrypt {
   
    private static CountDownLatch latch = new CountDownLatch(8);
    private static int threads; 
    
    public static void main(String[] args) throws JCryptUtil.Problem, InterruptedException, BrokenBarrierException {

        JCryptUtil.Options opts = JCryptUtil.parseOptions(args);
        CyclicBarrier barrier = new CyclicBarrier(opts.filenames.length+1);
        threads = opts.threads;
        long starttime = System.nanoTime();
        
        
       /* // CheckPoint 21
        for (int i = 0; i < opts.filenames.length; i++) {
            (new MyThread(opts, i, barrier)).start();                           // start worker threads
        }
        try {
            barrier.await();                                                    // main thread waits at barrier for worker threads
        } catch (InterruptedException ex) {
            Logger.getLogger(JCrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BrokenBarrierException ex) {
            Logger.getLogger(JCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Time taken: " + (System.nanoTime() - starttime) / 1000000000.0 + "s");
      */

        
   /*    // CheckPoint 22 
        ExecutorService exec = Executors.newFixedThreadPool(opts.threads);      // Number of threads in thread pool == command line -t arg
       
        for(int i = 0; i < opts.filenames.length; i++) {
            exec.execute(new MyRunnable(opts, i, latch));                       // add jobs to thread pool
        }
        exec.shutdown();                                                        // shutdown thread pool
        try {
          //  System.out.println("waiting on latch...");
            latch.await();                                                      // main thread waits for other threads
        } catch (InterruptedException ex) {
            System.out.println("interrupted ex");
        }
        
        System.out.println("Time taken: " + (System.nanoTime() - starttime) / 1000000000.0 + "s");
   */    
    
   
   
   
        // CheckPoint 23   
       
        JCrypt.process(opts, 0);    
        System.out.println("Main thread finished...");
   
        
    }

    public static void process(JCryptUtil.Options opts, int index) throws JCryptUtil.Problem {
        byte[] decryptedText = null;
        if (opts.decryptionPassword.length() > 0) { // option requests file to be decrypted
            System.out.println("Decrypting " + opts.filenames[index]);
            JCryptUtil.EncryptedData encryptedText = JCryptUtil.readEncryptedFile(opts.filenames[index]);
            decryptedText = JCryptUtil.decrypt(opts.decryptionPassword, encryptedText);
        } else if (opts.crack) { // option requests file to be cracked
            System.out.println("Cracking " + opts.filenames[index]);
            JCryptUtil.EncryptedData encryptedText = JCryptUtil.readEncryptedFile(opts.filenames[index]);
            decryptedText = crack(encryptedText);

        }
        if (opts.encryptionPassword.length() > 0) { // option requests file to be encrypted
            System.out.print("Encrypting " + opts.filenames[index]); 
            JCryptUtil.EncryptedData encryptedText;
            if (decryptedText == null) {
                byte[] buf = JCryptUtil.readRawFile(opts.filenames[index]);
                encryptedText = JCryptUtil.encrypt(opts.encryptionPassword, buf);
            } else {
                encryptedText = JCryptUtil.encrypt(opts.encryptionPassword, decryptedText);
            }
            System.out.println(" (checksum: " + encryptedText.checksum + ")");
            if (opts.saveToFile) { // save encrypted data to file
                JCryptUtil.writeEncryptedFile(encryptedText, new File(opts.filenames[index]).getPath() + ".encrypted");                
            } else { // print encrypted data to standard out
                System.out.println(new String(encryptedText.content));
            }
        } else if (opts.saveToFile) { // save decrypted data to file
            File file = new File(opts.filenames[index]);
            String filename = (file).getName();
            if (filename.substring(filename.length() - ".encrypted".length()).equalsIgnoreCase(".encrypted")) {
                filename = filename.substring(0, filename.length() - ".encrypted".length());
            } else {
                filename = filename + ".decrypted";
            }
            JCryptUtil.writeRawFile(decryptedText, file.getParent() + File.separator +filename);

        } else { // print decrypted data to standard out
            System.out.println(new String(decryptedText));
        }
    }

    public static byte[] crack(JCryptUtil.EncryptedData ciphertext) throws JCryptUtil.Problem {
        byte[] decryptedText = null;    
        int start = 0, stop = 8;
        
        
        ExecutorService exec = Executors.newFixedThreadPool(8);           // Number of threads in thread pool == -t arg
        
        
        for(int i = 0; i < 8; i++ ) {
            if(i == 7) { start = 56; stop = 62; }
            exec.execute(new CrackThread(start, stop, ciphertext, latch));                   // add tasks to thread pool     
            start+=8; stop+=8;
            // 0: start = 0 stop = 8
            // 1: start = 8 stop = 16
            // 2: start = 16 stop = 24
            // 3: start = 24 stop = 32
            // 4: start = 32 stop = 40
            // 5: start = 40 stop = 48
            // 6: start = 48 stop = 56
            // 7: start = 56 stop = 62
        }
        exec.shutdown(); 
        try {
            latch.await();
        } catch (InterruptedException ex) {
            Logger.getLogger(JCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        DecryptedText DT = new DecryptedText();
        decryptedText = DT.getDT();
        return decryptedText;
    }

}
