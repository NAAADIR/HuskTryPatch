package android.opengl;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class ResizeMailboxTest {
    public static void main(String[] args) throws Exception {
        ResizeMailbox box = new ResizeMailbox();
        box.put(100, 200);
        box.put(300, 400);
        if (box.take() != (((long) 300 << 32) | 400)) throw new AssertionError("latest size");
        if (box.take() != 0) throw new AssertionError("consume once");
        box.put(0, 100);
        if (box.take() != 0) throw new AssertionError("invalid size");

        CountDownLatch attempted = new CountDownLatch(1);
        Thread writer;
        synchronized (box) {
            box.put(10, 20);
            writer = new Thread(() -> { attempted.countDown(); box.put(30, 40); });
            writer.start();
            if (!attempted.await(5, TimeUnit.SECONDS)) throw new AssertionError("writer did not start");
            if (box.take() != (((long) 10 << 32) | 20)) throw new AssertionError("first size");
        }
        writer.join(5000);
        if (writer.isAlive()) throw new AssertionError("writer blocked");
        if (box.take() != (((long) 30 << 32) | 40)) throw new AssertionError("concurrent size lost");
        System.out.println("resize mailbox checks passed");
    }
}
