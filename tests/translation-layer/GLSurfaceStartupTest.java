package android.opengl;

import android.content.ContextWrapper;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

public final class GLSurfaceStartupTest {
    private static final class Renderer implements GLSurfaceView.Renderer {
        int width, height, initWidth, initHeight, calls;
        public void onSurfaceCreated(GL10 gl, EGLConfig config) { initWidth = width; initHeight = height; calls++; }
        public void onSurfaceChanged(GL10 gl, int w, int h) {}
        public void onDrawFrame(GL10 gl) {}
    }
    private static final class View extends GLSurfaceView {
        GLSurfaceStartupTest.Renderer game;
        View() { super(new ContextWrapper(null)); }
        @Override public boolean isAttachedToWindow() { return true; }
        void attach() { onAttachedToWindow(); }
        void size(int w, int h) { game.width = w; game.height = h; }
    }
    private static void check(boolean b, String msg) { if (!b) throw new AssertionError(msg); }
    public static void main(String[] args) {
        View view = new View(); Renderer game = new Renderer(); view.game = game;
        view.setRenderer(game);
        view.attach();
        check(husk.Native.starts == 0, "started before size and surface creation");
        view.size(1170, 2532);
        view.surfaceCreated(view.getHolder());
        check(husk.Native.starts == 1 && game.calls == 1, "renderer did not start once");
        check(game.initWidth == 1170 && game.initHeight == 2532, "renderer initialized with stale size");
        view.surfaceCreated(view.getHolder());
        check(husk.Native.starts == 1, "renderer restarted");
        View late = new View(); Renderer second = new Renderer(); late.game = second;
        late.size(640, 960); late.surfaceCreated(late.getHolder());
        check(husk.Native.starts == 1, "started without renderer");
        late.setRenderer(second);
        check(husk.Native.starts == 2 && second.initWidth == 640 && second.initHeight == 960, "late renderer did not start");
        View lost = new View(); Renderer third = new Renderer(); lost.game = third;
        lost.size(320, 568); lost.surfaceCreated(lost.getHolder()); lost.surfaceDestroyed(lost.getHolder());
        lost.setRenderer(third);
        check(husk.Native.starts == 2, "started after surface destruction");
        lost.surfaceCreated(lost.getHolder());
        check(husk.Native.starts == 3 && third.initWidth == 320 && third.initHeight == 568, "recreated surface did not start");
        lost.surfaceChanged(lost.getHolder(), 0, 320, 568);
        lost.surfaceDestroyed(lost.getHolder());
        check(!lost.huskHasSurface() && lost.huskTakeResize() == 0, "destroy did not discard old size");
        lost.surfaceChanged(lost.getHolder(), 0, 100, 200);
        check(lost.huskTakeResize() == 0, "accepted a change after destruction");
        lost.surfaceCreated(lost.getHolder());
        lost.surfaceChanged(lost.getHolder(), 0, 640, 960);
        check(lost.huskHasSurface() && lost.huskTakeResize() == (((long)640 << 32) | 960), "recreated surface size missing");
        View concurrent = new View(); Renderer fourth = new Renderer(); concurrent.game = fourth; concurrent.size(320, 568);
        Thread t1 = new Thread(() -> concurrent.setRenderer(fourth));
        Thread t2 = new Thread(() -> concurrent.surfaceCreated(concurrent.getHolder()));
        t1.start(); t2.start();
        try { t1.join(5000); t2.join(5000); } catch (InterruptedException e) { throw new AssertionError(e); }
        check(!t1.isAlive() && !t2.isAlive() && husk.Native.starts == 4, "concurrent startup stalled or registered twice");
        View interrupted = new View(); Renderer fifth = new Renderer(); interrupted.game = fifth; interrupted.size(320, 568);
        interrupted.setEGLContextFactory(new GLSurfaceView.EGLContextFactory() {
            boolean first = true;
            public javax.microedition.khronos.egl.EGLContext createContext(javax.microedition.khronos.egl.EGL10 e, javax.microedition.khronos.egl.EGLDisplay d, EGLConfig c) {
                if (first) { first = false; interrupted.surfaceDestroyed(interrupted.getHolder()); }
                return javax.microedition.khronos.egl.EGL10.EGL_NO_CONTEXT;
            }
            public void destroyContext(javax.microedition.khronos.egl.EGL10 e, javax.microedition.khronos.egl.EGLDisplay d, javax.microedition.khronos.egl.EGLContext c) {}
        });
        interrupted.setRenderer(fifth); interrupted.surfaceCreated(interrupted.getHolder());
        check(husk.Native.starts == 4, "registered after destruction during context creation");
        interrupted.surfaceCreated(interrupted.getHolder());
        check(husk.Native.starts == 5, "did not restart after interrupted context creation");
        System.out.println("GLSurfaceView startup ordering checks passed");
    }
}
