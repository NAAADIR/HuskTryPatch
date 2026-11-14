/* SPDX-License-Identifier: GPL-2.0-or-later */
import android.telephony.TelephonyManager;
import java.util.Locale;

public final class TelephonyNoSimTest {
    public static void main(String[] args) {
        Locale previous = Locale.getDefault();
        try {
            TelephonyManager manager = new TelephonyManager();
            for (Locale locale : new Locale[] { Locale.US, Locale.JAPAN, Locale.ROOT }) {
                Locale.setDefault(locale);
                if (manager.getSimState() != TelephonyManager.SIM_STATE_ABSENT ||
                    !manager.getSimCountryIso().equals(""))
                    throw new AssertionError("absent SIM must have no SIM provider country");
            }
        } finally {
            Locale.setDefault(previous);
        }
        System.out.println("TelephonyManager: absent SIM has no SIM country across locales: PASS");
    }
}
