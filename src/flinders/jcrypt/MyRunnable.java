package flinders.jcrypt;

import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MyRunnable implements Runnable {
    CountDownLatch latch;
    private JCryptUtil.Options opts;
    private int fileNumber;

        MyRunnable(JCryptUtil.Options opts, int fileNumber, CountDownLatch latch) {
            this.opts = opts;
            this.fileNumber = fileNumber;
            this.latch = latch;
        }

        @Override
        public void run() {
            try {
            JCrypt.process(this.opts, this.fileNumber);    // Process given file
            } catch (JCryptUtil.Problem ex) {
                Logger.getLogger(MyThread.class.getName()).log(Level.SEVERE, null, ex);
            }  
            latch.countDown();                             
        }

}
