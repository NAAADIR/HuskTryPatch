package android.opengl;

/** Latest surface size, atomically consumed by the render thread. */
final class ResizeMailbox {
    private long pending;

    void put(int width, int height) {
        synchronized (this) {
            if (width > 0 && height > 0) pending = ((long) width << 32) | (height & 0xffffffffL);
        }
    }

    long take() {
        synchronized (this) {
            long result = pending;
            pending = 0;
            return result;
        }
    }
}
