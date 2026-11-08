package husk;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;

/** Exercises the broker callback and local one-way Binder behavior. */
public final class GmsCallbackTest {
    private static void check(boolean value) { if (!value) throw new AssertionError(); }

    public static void main(String[] args) throws Exception {
        final Runnable[] pending = new Runnable[1];
        GmsCore.sPost = r -> pending[0] = r;
        final boolean[] called = {false};
        Binder callback = new Binder() {
            @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                check(code == 1 && flags == 0 && reply != null);
                data.enforceInterface(GmsCore.CALLBACKS);
                check(data.readInt() == 16 && data.readStrongBinder() == null && data.readInt() == 0);
                called[0] = true;
                reply.writeNoException();
                return true;
            }
        };
        Parcel request = Parcel.obtain(), response = Parcel.obtain();
        request.writeInterfaceToken(GmsCore.BROKER);
        request.writeStrongBinder(callback);
        request.writeInt(1); request.writeInt(0xffff4f45); request.writeInt(8);
        request.writeInt(0x00040002); request.writeInt(91);
        check(new GmsCore.Broker().transact(46, request, response, 0));
        response.readException();
        check(pending[0] != null && !called[0]);
        pending[0].run();
        check(called[0]);
        request.recycle(); response.recycle();

        Parcel input = Parcel.obtain();
        check(new Binder() {
            @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                check(reply == null && flags == IBinder.FLAG_ONEWAY);
                return true;
            }
        }.transact(1, input, null, IBinder.FLAG_ONEWAY));
        try {
            new Binder() {
                @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                    reply.writeNoException();
                    return true;
                }
            }.transact(1, input, null, IBinder.FLAG_ONEWAY);
            throw new AssertionError("expected null reply failure");
        } catch (NullPointerException expected) {
            // Documents the failure when a local callback assumes a reply exists.
        } finally { input.recycle(); }
        System.out.println("Gms callback and one-way Binder behavior ok");
    }
}
