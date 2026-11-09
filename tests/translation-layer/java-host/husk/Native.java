package husk;
public final class Native {
    public static int starts;
    public static void startGL(Object view, Object renderer, int version) {
        starts++;
        ((android.opengl.GLSurfaceView.Renderer) renderer).onSurfaceCreated(null, null);
    }
    public static void requestRender() {}
}
