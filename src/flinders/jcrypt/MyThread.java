package flinders.jcrypt;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MyThread extends Thread {
    
    private CyclicBarrier barrier;
    
    private JCryptUtil.Options opts;
    private int fileNumber;
    
    
    public MyThread(JCryptUtil.Options opts, int filesNumber, CyclicBarrier barrier) {
        this.opts = opts;
        this.fileNumber = fileNumber;
        this.barrier = barrier;
    }
    
    @Override
    public void run() {       
        try {
            JCrypt.process(this.opts, this.fileNumber);                            // Process given file
        } catch (JCryptUtil.Problem ex) {
            Logger.getLogger(MyThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            barrier.await();                                                      // Wait at barrier
        } catch (InterruptedException ex) {
            Logger.getLogger(MyThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BrokenBarrierException ex) {
            Logger.getLogger(MyThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    
}
