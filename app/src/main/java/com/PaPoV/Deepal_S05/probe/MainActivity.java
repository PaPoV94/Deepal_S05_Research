package com.PaPoV.Deepal_S05.probe;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Read-only reconnaissance of this head unit, for the owner's own device.
 * - Dumps every installed package with its exported components + the permission each requires.
 * - Copies the launcher APK and any APK whose package/component names look climate/car/voice/card related.
 * - Fires a normal runtime permission request so we can see whether that dialog appears at all.
 * Output goes to this app's external files dir (reachable by a file manager, no storage permission needed).
 */
public class MainActivity extends Activity {

    private TextView log;
    private EditText shellInput;
    private File outDir;

    private static final String[] KEYWORDS = {
            "launcher", "home", "desktop", "card", "widget",
            "hvac", "climate", "aircon", "thermal", "temp", "aircondition",
            "car", "vehicle", "auto", "tinnove", "autopai", "auto-pai", "changan", "deepal",
            "voice", "speech", "assistant", "aiui", "iflytek", "xf",
            "settings", "systemui", "sysui",
            "engineer", "factory", "diag", "fty", "eng", "debug", "adb", "develop", "emode"
    };

    // Specific packages found by name in packages_dump.txt that are still worth a static
    // (offline) look: the engineering-menu family (ADB/USB toggle investigation) and the
    // power/background-kill family (suspected of killing the washer-sensor BLE scan). Dropped
    // de.szalkowski.activitylauncher.rustore_fork / com.jami.tool.hiddensetting / com.apps.
    // settings / pl.solidexplorer2 / ru.example.appmanager.tmgaming - those are the user's own
    // known utility apps, nothing to investigate there.
    private static final String[] FOCUSED_TARGETS = {
            "com.adayo.app.emode",
            "com.adayo.app.autotest",
            "com.adayo.app.dynomode",
            "com.wt.maintenance",
            "com.android.car.developeroptions",
            "com.android.providers.settings",
            "com.incall.apps.softmanager",
            "com.wtcl.filemanager",
            "com.adayo.app.dvr",
            "com.adayo.app.apa",
            "com.cleaner.booster.battery.security.master",
            "com.adayo.app.powermanager",
            "com.wt.vehiclecenter",
            "com.wt.airconditioner",
            "com.tinnove.link.client",
            "com.tinnove.systemservice",
            "com.wt.tinnovecoreservice",
            "com.autopai.sceneengine",
            "com.autopai.theme.rescarmodel",
            "com.android.systemui",
            "com.autopai.car.dialer"
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        sv.addView(root);

        outDir = getExternalFilesDir(null);

        Button runBtn = new Button(this);
        runBtn.setText("1) DUMP + COPY APKs");
        root.addView(runBtn);

        Button btBtn = new Button(this);
        btBtn.setText("2) TEST runtime permission dialog (Bluetooth)");
        root.addView(btBtn);

        Button focusBtn = new Button(this);
        focusBtn.setText("3) COPY engineering-menu / power-mgmt candidates only");
        root.addView(focusBtn);

        Button usbBtn = new Button(this);
        usbBtn.setText("4) CHECK EMode ADB-gate (USB disk + car power state)");
        root.addView(usbBtn);

        Button polyBtn = new Button(this);
        polyBtn.setText("5) CHECK polymeric_service (hidden ServiceManager API)");
        root.addView(polyBtn);

        Button fwBtn = new Button(this);
        fwBtn.setText("6) COPY /system/framework jars (services.jar etc.)");
        root.addView(fwBtn);

        Button adbKeyBtn = new Button(this);
        adbKeyBtn.setText("7) TRY writing adbkey.pub (from USB) to /adb_keys");
        root.addView(adbKeyBtn);

        Button devSettingsBtn = new Button(this);
        devSettingsBtn.setText("8) CHECK dev-settings unlock (restriction + adb_enabled write)");
        root.addView(devSettingsBtn);

        Button grantCheckBtn = new Button(this);
        grantCheckBtn.setText("9) CHECK actually-granted permissions on other system apps");
        root.addView(grantCheckBtn);

        Button godModeBtn = new Button(this);
        godModeBtn.setText("10) GOD MODE: enable adb_enabled + write adb_keys to /data/misc/adb");
        root.addView(godModeBtn);

        Button adbDialogBtn = new Button(this);
        adbDialogBtn.setText("11) CHECK/TRY the 'Allow USB debugging?' confirmation screen directly");
        root.addView(adbDialogBtn);

        Button shellBtn = new Button(this);
        shellBtn.setText("12) GRANT SYSTEM_ALERT_WINDOW to com.deepal.voiceassist (no ADB)");
        root.addView(shellBtn);

        Button voskLogBtn = new Button(this);
        voskLogBtn.setText("13) READ logcat for VoskEngine/AndroidRuntime (voiceassist model unpack)");
        root.addView(voskLogBtn);

        Button clearPreferredBtn = new Button(this);
        clearPreferredBtn.setText("14) CLEAR preferred-activities for com.tinnove.aiassistant (no ADB)");
        root.addView(clearPreferredBtn);

        // 15) Generic shell runner - the actual answer to "we need adb for this": Runtime.exec()
        // from this process inherits android.uid.system (confirmed via button 10's myUid=1000),
        // so whatever would normally go through 'adb shell <cmd>' can run directly from here,
        // no cable/USB authorization needed at all. Covers dumpsys, pm, logcat with arbitrary
        // filters, cat'ing any file readable by system, etc. - one general tool instead of a new
        // dedicated button per question.
        shellInput = new EditText(this);
        shellInput.setHint("shell command, e.g. dumpsys package com.tinnove.aiassistant");
        shellInput.setSingleLine(false);
        root.addView(shellInput);

        Button runShellBtn = new Button(this);
        runShellBtn.setText("15) RUN shell command above (as system, no ADB)");
        root.addView(runShellBtn);

        Button usbCommandsBtn = new Button(this);
        usbCommandsBtn.setText("16) RUN commands.txt from USB stick (no on-screen typing)");
        root.addView(usbCommandsBtn);

        Button adbCaptureBtn = new Button(this);
        adbCaptureBtn.setText("17) SWITCH to adb mode + CAPTURE live key exchange (30s, no stick needed)");
        root.addView(adbCaptureBtn);

        Button directAuthBtn = new Button(this);
        directAuthBtn.setText("18) DIRECTLY AUTHORIZE this laptop's key (bypass the broken dialog)");
        root.addView(directAuthBtn);

        // 19/20) Continuous logcat capture - for catching a one-off event (a toast/warning that
        // appears while driving, where there's no time to react and start logcat at that exact
        // moment) without needing the laptop plugged in when it happens. logcat's own -f/-r/-n
        // flags do the file writing and rotation natively in the child process, so it keeps
        // running (reparented to init) even if this Activity/app is killed - start it once,
        // drive around, come back later and pull the file.
        Button startLogBtn = new Button(this);
        startLogBtn.setText("19) START continuous logcat capture (survives app kill, for catching one-off toasts)");
        root.addView(startLogBtn);

        Button stopLogBtn = new Button(this);
        stopLogBtn.setText("20) STOP continuous logcat capture");
        root.addView(stopLogBtn);

        log = new TextView(this);
        log.setTextIsSelectable(true);
        root.addView(log);

        setContentView(sv);

        append("Output folder:\n" + (outDir == null ? "null" : outDir.getAbsolutePath()));
        append("Open it in a file manager, copy the files to a USB stick, send them back.\n");
        append("Android " + Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")");
        append("Device: " + Build.MANUFACTURER + " / " + Build.MODEL + " / " + Build.PRODUCT);
        append("Fingerprint: " + Build.FINGERPRINT + "\n");

        runBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { runDumpAndCopy(); }
        });
        btBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { testRuntimePermission(); }
        });
        focusBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { runFocusedCopy(); }
        });
        usbBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { checkUsbDetection(); }
        });
        polyBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { checkPolymericService(); }
        });
        fwBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { copyFrameworkJars(); }
        });
        adbKeyBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { tryWriteAdbKey(); }
        });
        devSettingsBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { checkDevSettingsUnlock(); }
        });
        grantCheckBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { checkGrantedPermissions(); }
        });
        godModeBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { godMode(); }
        });
        adbDialogBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { checkAdbConfirmationScreen(); }
        });
        shellBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { grantVoiceAssistOverlay(); }
        });
        voskLogBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { readVoskLog(); }
        });
        clearPreferredBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { clearAiAssistantPreferred(); }
        });
        runShellBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { runShellCommand(); }
        });
        usbCommandsBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { runUsbCommandsFile(); }
        });
        adbCaptureBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { captureAdbKeyExchange(); }
        });
        directAuthBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { directlyAuthorizeAdbKey(); }
        });
        startLogBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { startContinuousLogcat(); }
        });
        stopLogBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { stopContinuousLogcat(); }
        });
    }

    // Survives this Activity/process being killed - it's a separate child process (reparented to
    // init), not a thread of this one. A static field only helps STOP it from the same app
    // lifetime; if the app process itself dies, "logcat -f ..." keeps writing regardless, and a
    // fresh launch of DeepalProbe can't rediscover the old Process handle - button 20 will then
    // report "not running from this session" even though the file is still growing. Kill it by
    // filename (pkill/ps+kill via button 15) if that happens, or just let -n cap the total size.
    private static Process continuousLogcatProcess;
    private static final String CONTINUOUS_LOGCAT_FILENAME = "continuous_logcat.txt";

    private void startContinuousLogcat() {
        if (continuousLogcatProcess != null) {
            append("\n(continuous logcat already running from this session - stop it first if you want to restart)");
            return;
        }
        final File logFile = new File(outDir, CONTINUOUS_LOGCAT_FILENAME);
        append("\n=== Starting continuous logcat -> " + logFile.getAbsolutePath() + " ===");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder sb = new StringBuilder();
                try {
                    Runtime.getRuntime().exec(new String[]{"logcat", "-c"}).waitFor();
                    // -r4096 -n5: rotate every 4MB, keep 5 files (~20MB total) - old entries fall
                    // off automatically so this can be left running indefinitely without filling
                    // storage. No tag filter (plain *:V default) since we don't know the source.
                    Process p = Runtime.getRuntime().exec(new String[]{
                            "logcat", "-v", "threadtime",
                            "-f", logFile.getAbsolutePath(), "-r", "4096", "-n", "5"});
                    continuousLogcatProcess = p;
                    sb.append("Started, pid-holding process object stored.\n");
                    sb.append("Trigger the warning you're after, then press 20 (or just pull the file later -\n");
                    sb.append("it keeps writing even if this app is closed/killed).\n");
                    sb.append("File: ").append(logFile.getAbsolutePath()).append("\n");
                } catch (Throwable t) {
                    sb.append("Failed to start: ").append(t).append("\n");
                }
                append(sb.toString());
            }
        }).start();
    }

    private void stopContinuousLogcat() {
        append("\n=== Stopping continuous logcat ===");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder sb = new StringBuilder();
                if (continuousLogcatProcess != null) {
                    continuousLogcatProcess.destroy();
                    continuousLogcatProcess = null;
                    sb.append("Destroyed the process handle held by this session.\n");
                } else {
                    sb.append("No process handle in this session (either never started here, or\n");
                    sb.append("this app was restarted since) - looking for a leftover 'logcat' process\n");
                    sb.append("writing to ").append(CONTINUOUS_LOGCAT_FILENAME).append(" and killing it directly...\n");
                    try {
                        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c",
                                "pkill -f '" + CONTINUOUS_LOGCAT_FILENAME + "'"});
                        p.waitFor();
                        sb.append("pkill exit=").append(p.exitValue()).append(" (0 = found and killed something)\n");
                    } catch (Throwable t) {
                        sb.append("pkill attempt failed: ").append(t).append("\n");
                    }
                }
                File logFile = new File(outDir, CONTINUOUS_LOGCAT_FILENAME);
                sb.append("File on disk: ").append(logFile.getAbsolutePath())
                        .append(" (").append(logFile.length()).append(" bytes)\n");
                append(sb.toString());
            }
        }).start();
    }

    /**
     * The actual goal was never "make the dialog appear" - it's "get this laptop's key trusted".
     * AdbDebuggingManager.allowDebugging(alwaysAllow, key) (case 3 of its Handler, see
     * services_src) is an ordinary IAdbManager Binder call - exactly what a working dialog's
     * "Allow" button would invoke - and nothing stops this android.uid.system process from
     * calling it directly via ServiceManager.getService("adb"). Case 3 only checks
     * getFingerprints(key).equals(mFingerprints) (an MD5 of the base64 blob BEFORE the first
     * whitespace - tolerant of the " user@host" comment) before sending "OK" to adbd over the
     * local socket, so passing our own already-known ADB_PUBLIC_KEY (same one god mode wrote to
     * the key files) succeeds as long as it's done while mFingerprints still reflects a pending
     * request for that same key.
     *
     * The obstacle is timing, not permission: CLAUDE.md's "ADB по кабелю" finding showed the
     * broken UsbDebuggingActivity stub auto-denies ~50ms after a PK request starts it, via case 4
     * (AdbDebuggingManager.this.mThread.sendResponse("NO")) triggered from its onDestroy(). This
     * disables that Activity component first (PackageManager.setComponentEnabledSetting - no
     * special permission needed, CHANGE_COMPONENT_ENABLED_STATE is a signature permission
     * auto-granted by the shared platform signature, same mechanism as WRITE_SECURE_SETTINGS) so
     * resolveActivity() finds nothing, startConfirmationActivity() returns false, and
     * AdbDebuggingManager just logs an error and returns WITHOUT ever sending "NO" - the request
     * stays genuinely pending with no race until this code calls allowDebugging() itself. Restores
     * the component's default enabled state afterward regardless of outcome, to leave the system
     * as close to untouched as possible.
     */
    private static final String[] ADB_UI_COMPONENTS = {
            "com.android.systemui/com.android.systemui.usb.UsbDebuggingActivity",
            "com.android.systemui/com.android.systemui.usb.UsbDebuggingSecondaryUserActivity"
    };

    private void directlyAuthorizeAdbKey() {
        append("\n=== Direct ADB key authorization (bypass broken dialog) - working... ===");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder sb = new StringBuilder("\n=== Direct ADB key authorization ===\n");
                PackageManager pm = getPackageManager();
                List<android.content.ComponentName> disabled = new ArrayList<android.content.ComponentName>();

                // Full-sequence live logcat capture - the previous run of this button showed no
                // exception and "adb devices" still said unauthorized, which tells us nothing
                // about WHY: allowDebugging() just does mHandler.sendMessage() and returns, so
                // "completed without throwing" is guaranteed either way. Only the Handler's own
                // case 3 log output (fingerprint match/mismatch, "OK" sent or not) and adbd's own
                // reaction to it can show what actually happened - so capture logcat across the
                // ENTIRE sequence (disable -> switch USB -> wait -> call -> wait for the
                // Handler/adbd to react -> restore), not just a snapshot before/after.
                final StringBuilder logBuf = new StringBuilder();
                Process logcatProcess = null;
                Thread logcatReaderThread = null;
                try {
                    Runtime.getRuntime().exec(new String[]{"logcat", "-c"}).waitFor();
                    final Process lp = Runtime.getRuntime().exec(new String[]{
                            "logcat", "-v", "threadtime",
                            "AdbDebuggingManager:V", "UsbDebuggingActivity:V", "adbd:V",
                            "ActivityTaskManager:V", "AndroidRuntime:V", "*:S"});
                    logcatProcess = lp;
                    logcatReaderThread = new Thread(new Runnable() {
                        public void run() {
                            try {
                                java.io.BufferedReader br = new java.io.BufferedReader(
                                        new java.io.InputStreamReader(lp.getInputStream()));
                                String line;
                                while ((line = br.readLine()) != null) {
                                    synchronized (logBuf) { logBuf.append(line).append("\n"); }
                                }
                                br.close();
                            } catch (Throwable ignored) {
                            }
                        }
                    });
                    logcatReaderThread.start();
                } catch (Throwable t) {
                    sb.append("logcat capture setup failed: ").append(t).append("\n");
                }

                sb.append("-- Disabling the broken confirmation Activity --\n");
                for (String cs : ADB_UI_COMPONENTS) {
                    android.content.ComponentName cn = android.content.ComponentName.unflattenFromString(cs);
                    try {
                        pm.setComponentEnabledSetting(cn, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
                        disabled.add(cn);
                        sb.append("  disabled: ").append(cs).append("\n");
                    } catch (Throwable t) {
                        sb.append("  FAILED to disable ").append(cs).append(": ").append(t).append("\n");
                    }
                }

                try {
                    sb.append("\n-- Switching USB role to adb (fresh connection attempt) --\n");
                    String[] usbSwitchCmds = {
                            "setprop sys.usb.config none",
                            "setprop usb.carplay.state in",
                            "setprop sys.usb.config adb"
                    };
                    for (String cmd : usbSwitchCmds) {
                        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
                        int code = p.waitFor();
                        sb.append("  ").append(cmd).append("  exit=").append(code).append("\n");
                    }
                    append("Switched USB to adb mode - if the laptop is plugged in, its adb client\n" +
                            "should auto-detect the re-enumerated device. Waiting 5s...");
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) {}

                    sb.append("\n-- Calling IAdbManager.allowDebugging(true, <laptop key>) directly --\n");
                    try {
                        Class<?> smCls = Class.forName("android.os.ServiceManager");
                        Object adbBinder = smCls.getMethod("getService", String.class).invoke(null, "adb");
                        if (adbBinder == null) {
                            sb.append("  ServiceManager.getService(\"adb\") returned null\n");
                        } else {
                            Class<?> iAdbManagerStub = Class.forName("android.debug.IAdbManager$Stub");
                            Object iAdbManager = iAdbManagerStub.getMethod("asInterface", android.os.IBinder.class)
                                    .invoke(null, adbBinder);
                            iAdbManager.getClass().getMethod("allowDebugging", boolean.class, String.class)
                                    .invoke(iAdbManager, true, ADB_PUBLIC_KEY);
                            sb.append("  allowDebugging(true, ...) call completed without throwing.\n")
                              .append("  (this only means the Binder call itself didn't throw - it\n")
                              .append("   just enqueues a Handler message; see the logcat section\n")
                              .append("   below for whether the fingerprint actually matched.)\n");
                        }
                    } catch (Throwable t) {
                        sb.append("  allowDebugging call failed: ").append(t).append("\n");
                    }

                    // Give the Handler/adbd a few seconds to actually process case 3 and react
                    // (send "OK", persist the key, etc.) before we stop capturing and restore the
                    // activity - this is exactly the window the previous run never captured.
                    try { Thread.sleep(4000); } catch (InterruptedException ignored) {}
                } catch (Throwable t) {
                    sb.append("FATAL: ").append(t).append("\n");
                } finally {
                    sb.append("\n-- Re-enabling the confirmation Activity (restore default state) --\n");
                    for (android.content.ComponentName cn : disabled) {
                        try {
                            pm.setComponentEnabledSetting(cn, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT, PackageManager.DONT_KILL_APP);
                            sb.append("  restored: ").append(cn.flattenToString()).append("\n");
                        } catch (Throwable t) {
                            sb.append("  FAILED to restore ").append(cn.flattenToString()).append(": ").append(t).append("\n");
                        }
                    }
                }

                if (logcatProcess != null) {
                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                    logcatProcess.destroy();
                    try {
                        if (logcatReaderThread != null) logcatReaderThread.join(2000);
                    } catch (InterruptedException ignored) {
                    }
                }
                sb.append("\n-- Live logcat across the whole sequence --\n");
                synchronized (logBuf) {
                    if (logBuf.length() == 0) sb.append("(nothing captured for these tags)\n");
                    else sb.append(logBuf);
                }

                sb.append("\n-- /data/misc/adb/adb_keys after --\n");
                dumpKeyFile(sb, "/data/misc/adb/adb_keys");

                append(sb.toString());
                try {
                    File f = new File(outDir, "direct_adb_authorize_result.txt");
                    PrintWriter pw = new PrintWriter(new FileOutputStream(f));
                    pw.print(sb.toString());
                    pw.close();
                    append("Wrote " + f.getName());
                } catch (Throwable t) {
                    append("could not write direct_adb_authorize_result.txt: " + t);
                }
            }
        }).start();
    }

    /**
     * Decompiling AdbDebuggingManager (services_src) this session showed case 5 of its Handler
     * (triggered by listenToSocket() parsing a "PK<key>" message from adbd) ALWAYS calls
     * startConfirmationForKey() unconditionally - isKeyAuthorized()/mKeyMap are never consulted
     * on that path, and in fact isKeyAuthorized() has no other caller anywhere in services.jar.
     * That means the PK-vs-CK decision (ask for confirmation vs already-trusted) is made by the
     * NATIVE adbd daemon itself reading its own copy of the key files, not by this Java class -
     * so god mode's late write to /data/misc/adb/adb_keys may simply not have been seen by an
     * adbd that was already running. This button settles what the framework side sees DURING a
     * real connection attempt without guessing: clear logcat, capture a fixed window with the
     * daemon/activity/handler tags, then dump both key files with per-line length so an invisible
     * trailing space/newline mismatch would show up directly. Everything is written to one file
     * at the end from this same thread (not split across a second async append like button 11's
     * check), so an incomplete read from the USB stick mid-capture can't truncate the result.
     *
     * First real run (2026-10-29) showed nothing but a repeating
     * "Caught an exception opening the socket: ... No such file or directory" every ~2s for the
     * whole window - i.e. adbd itself was not running (the port was still in USB-host/mass-storage
     * mode for the flash drive used to install/run this APK), so the key exchange never had a
     * chance to happen at all. Folding the proven-working USB-role switch
     * (sys.usb.config=none -> usb.carplay.state=in -> sys.usb.config=adb, confirmed working via
     * commands.txt in an earlier session) into this same button removes that race entirely - no
     * flash drive or on-screen typing needed, and the result still lands in this app's internal
     * outDir, unaffected by the stick dropping out once the port flips to device mode.
     */
    private void captureAdbKeyExchange() {
        append("\n=== Switching USB port to adb mode, then capturing 30s - run trigger_adb_connect on the laptop NOW ===");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder sb = new StringBuilder("\n=== ADB key exchange capture ===\n");

                sb.append("-- Switching USB role to adb --\n");
                String[] usbSwitchCmds = {
                        "setprop sys.usb.config none",
                        "setprop usb.carplay.state in",
                        "setprop sys.usb.config adb"
                };
                for (String cmd : usbSwitchCmds) {
                    try {
                        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
                        int code = p.waitFor();
                        sb.append("  ").append(cmd).append("  exit=").append(code).append("\n");
                    } catch (Throwable t) {
                        sb.append("  ").append(cmd).append("  FAILED: ").append(t).append("\n");
                    }
                }
                try {
                    Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c",
                            "getprop sys.usb.config; getprop init.svc.adbd"});
                    sb.append("  readback (sys.usb.config / init.svc.adbd):\n  ").append(readAll(p.getInputStream())).append("\n");
                    p.waitFor();
                } catch (Throwable t) {
                    sb.append("  readback failed: ").append(t).append("\n");
                }
                try { Thread.sleep(1500); } catch (InterruptedException ignored) {}

                try {
                    Runtime.getRuntime().exec(new String[]{"logcat", "-c"}).waitFor();
                } catch (Throwable t) {
                    sb.append("logcat -c failed: ").append(t).append("\n");
                }
                try {
                    final Process p = Runtime.getRuntime().exec(new String[]{
                            "logcat", "-v", "threadtime",
                            "AdbDebuggingManager:V", "UsbDebuggingActivity:V", "adbd:V",
                            "ActivityTaskManager:V", "AndroidRuntime:V", "*:S"});
                    Thread killer = new Thread(new Runnable() {
                        public void run() {
                            try { Thread.sleep(30000); } catch (InterruptedException ignored) {}
                            p.destroy();
                        }
                    });
                    killer.start();
                    java.io.BufferedReader br = new java.io.BufferedReader(
                            new java.io.InputStreamReader(p.getInputStream()));
                    String line;
                    int n = 0;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                        n++;
                    }
                    br.close();
                    sb.append("(captured ").append(n).append(" line(s))\n");
                    if (n == 0) {
                        sb.append("-> NOTHING logged for these tags in 30s. Either adbd never sent\n")
                          .append("   PK/CK for this attempt, or the attempt happened outside the\n")
                          .append("   window - retry and plug/replug the cable RIGHT AFTER pressing\n")
                          .append("   this button, not before.\n");
                    }
                } catch (Throwable t) {
                    sb.append("logcat capture failed: ").append(t).append("\n");
                }

                sb.append("\n-- /data/misc/adb/adb_keys (per-line length + content) --\n");
                dumpKeyFile(sb, "/data/misc/adb/adb_keys");
                sb.append("\n-- /adb_keys (system pre-authorized keys) --\n");
                dumpKeyFile(sb, "/adb_keys");

                append(sb.toString());
                try {
                    File f = new File(outDir, "adb_key_exchange_capture.txt");
                    PrintWriter pw = new PrintWriter(new FileOutputStream(f));
                    pw.print(sb.toString());
                    pw.close();
                    append("Wrote " + f.getName());
                } catch (Throwable t) {
                    append("could not write adb_key_exchange_capture.txt: " + t);
                }
            }
        }).start();
    }

    private void dumpKeyFile(StringBuilder sb, String path) {
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(path));
            String line;
            int n = 0;
            while ((line = br.readLine()) != null) {
                n++;
                sb.append("  [").append(n).append("] len=").append(line.length())
                  .append(" '").append(line).append("'\n");
            }
            br.close();
            if (n == 0) sb.append("  (empty or unreadable)\n");
        } catch (Throwable t) {
            sb.append("  read failed: ").append(t).append("\n");
        }
    }

    /**
     * Same disk.isUsb() detection as checkUsbDetection() (reused rather than re-derived), but
     * instead of looking for safe.txt, reads a user-editable commands.txt from the stick's root -
     * one shell command per line, blank lines and lines starting with # ignored - runs each
     * through sh -c (inheriting android.uid.system like every other Runtime.exec() in this app).
     * Writes after EVERY command (not once at the end) to BOTH the stick's commands_result.txt
     * AND this app's own external-files dir (usb_commands_last_run.txt, on internal storage,
     * unaffected by the stick's presence) - a command that changes sys.usb.config (switching the
     * port's role between USB-host/mass-storage and USB-device/adb) can make the stick itself
     * disappear mid-run, so the USB-side write is best-effort per line while the internal copy is
     * the one guaranteed to have everything up to the point things changed.
     */
    private void runUsbCommandsFile() {
        append("\n=== Looking for commands.txt on a USB disk ===");
        new Thread(new Runnable() {
            final File internalLog = new File(outDir, "usb_commands_last_run.txt");
            File usbRoot;

            private void writeBoth(String text) {
                try {
                    PrintWriter pw = new PrintWriter(new FileOutputStream(internalLog, true));
                    pw.print(text);
                    pw.close();
                } catch (Throwable ignored) {
                }
                if (usbRoot != null) {
                    try {
                        PrintWriter pw = new PrintWriter(new FileOutputStream(new File(usbRoot, "commands_result.txt"), true));
                        pw.print(text);
                        pw.close();
                    } catch (Throwable ignored) {
                        // stick likely gone (e.g. sys.usb.config just flipped the port to device
                        // mode) - fine, internalLog already has it.
                    }
                }
            }

            public void run() {
                try {
                    PrintWriter clear = new PrintWriter(new FileOutputStream(internalLog, false));
                    clear.print("");
                    clear.close();
                } catch (Throwable ignored) {
                }
                String header = "\n=== USB commands.txt run ===\n";
                writeBoth(header);
                append(header);
                try {
                    Object storageManager = getSystemService("storage");
                    Method getVolumes = storageManager.getClass().getMethod("getVolumes");
                    List<?> volumes = (List<?>) getVolumes.invoke(storageManager);
                    if (volumes != null) {
                        for (Object vol : volumes) {
                            try {
                                Method getDisk = vol.getClass().getMethod("getDisk");
                                Object disk = getDisk.invoke(vol);
                                if (disk == null) continue;
                                Method isUsbM = disk.getClass().getMethod("isUsb");
                                if (!((Boolean) isUsbM.invoke(disk))) continue;
                                Method getPath = vol.getClass().getMethod("getPath");
                                Object pathFile = getPath.invoke(vol);
                                if (pathFile instanceof File) { usbRoot = (File) pathFile; break; }
                            } catch (Throwable ignored) {}
                        }
                    }
                    if (usbRoot == null) {
                        String msg = "No disk.isUsb()==true volume found - is the stick plugged into\n" +
                                "the head unit's own USB-A port?\n";
                        writeBoth(msg);
                        append(msg);
                        return;
                    }
                    String rootMsg = "USB root: " + usbRoot.getAbsolutePath() + "\n";
                    writeBoth(rootMsg);
                    append(rootMsg);

                    // Recovery: if the stick vanished mid-run last time (e.g. a command flipped
                    // the port's USB role), its commands_result.txt may be stale/incomplete -
                    // push a copy of last run's internal log onto the stick now, under a
                    // different name, before starting the new run. Costs nothing if there was no
                    // previous run (file just won't exist yet).
                    if (internalLog.exists() && internalLog.length() > 0) {
                        try {
                            copyFile(internalLog, new File(usbRoot, "usb_commands_PREVIOUS_run.txt"));
                            append("Recovered previous run's internal log onto the stick as usb_commands_PREVIOUS_run.txt\n");
                        } catch (Throwable ignored) {
                        }
                    }

                    File cmdFile = new File(usbRoot, "commands.txt");
                    if (!cmdFile.exists()) {
                        String msg = "commands.txt not found at " + cmdFile.getAbsolutePath() + "\n";
                        writeBoth(msg);
                        append(msg);
                        return;
                    }
                    java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(cmdFile));
                    String line;
                    int n = 0;
                    while ((line = br.readLine()) != null) {
                        String cmd = line.trim();
                        if (cmd.isEmpty() || cmd.startsWith("#")) continue;
                        n++;
                        StringBuilder step = new StringBuilder("\n--- [").append(n).append("] ").append(cmd).append(" ---\n");
                        try {
                            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
                            String out = readAll(p.getInputStream());
                            String err = readAll(p.getErrorStream());
                            int code = p.waitFor();
                            step.append("exit=").append(code).append("\n");
                            if (!out.isEmpty()) step.append(out).append("\n");
                            if (!err.isEmpty()) step.append("stderr:\n").append(err).append("\n");
                        } catch (Throwable t) {
                            step.append("exec failed: ").append(t).append("\n");
                        }
                        writeBoth(step.toString());
                        append(step.toString());
                    }
                    br.close();
                    if (n == 0) {
                        String msg = "commands.txt was empty (no non-comment lines)\n";
                        writeBoth(msg);
                        append(msg);
                    }
                } catch (Throwable t) {
                    String msg = "FATAL: " + t + "\n";
                    writeBoth(msg);
                    append(msg);
                }
                append("\n=== done, see " + internalLog.getAbsolutePath() + " (and commands_result.txt on the stick if it's still mounted) ===");
            }
        }).start();
    }

    private void runShellCommand() {
        final String cmd = shellInput.getText().toString().trim();
        if (cmd.isEmpty()) {
            append("\n(shell command box is empty)");
            return;
        }
        append("\n=== sh -c '" + cmd + "' ===");
        new Thread(new Runnable() {
            public void run() {
                StringBuilder sb = new StringBuilder("\n=== sh -c '" + cmd + "' ===\n");
                try {
                    Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
                    String out = readAll(p.getInputStream());
                    String err = readAll(p.getErrorStream());
                    int code = p.waitFor();
                    sb.append("exit=").append(code).append("\n");
                    if (!out.isEmpty()) sb.append("stdout:\n").append(out).append("\n");
                    if (!err.isEmpty()) sb.append("stderr:\n").append(err).append("\n");
                } catch (Throwable t) {
                    sb.append("exec failed: ").append(t).append("\n");
                }
                append(sb.toString());
                try {
                    File f = new File(outDir, "shell_last_output.txt");
                    PrintWriter pw = new PrintWriter(new FileOutputStream(f));
                    pw.print(sb.toString());
                    pw.close();
                } catch (Throwable ignored) {}
            }
        }).start();
    }

    /**
     * VoiceAssist's VoiceCommandActivity now shows its own status text correctly (the overlay
     * fix worked) but reports "Модель распознавания не найдена" - StorageService.unpack()
     * (Vosk-android helper) failed and called VoskEngine's onError, which logs
     * Log.e(TAG, "model unpack failed", e) before translating it into that message. The model
     * assets are confirmed present and correctly packaged inside the built APK (checked the zip
     * directly), so this is a runtime unpack/extraction problem, not a missing-file problem -
     * reading the actual exception is the fastest way to know why without guessing.
     */
    private void readVoskLog() {
        StringBuilder sb = new StringBuilder("\n=== logcat: VoskEngine / AndroidRuntime (voiceassist) ===\n");
        try {
            Process p = Runtime.getRuntime().exec(new String[]{
                    "logcat", "-d", "-t", "600",
                    "VoskEngine:*", "AndroidRuntime:*", "System.err:*", "*:S"});
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line;
            int n = 0;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
                n++;
            }
            br.close();
            p.waitFor();
            sb.append("(").append(n).append(" lines, exit=").append(p.exitValue()).append(")\n");
        } catch (Throwable t) {
            sb.append("logcat exec failed: ").append(t).append("\n");
        }
        append(sb.toString());
        try {
            File f = new File(outDir, "vosk_log.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write vosk_log.txt: " + t);
        }
    }

    /**
     * The steering-wheel VOICE_COMMAND/VOICE_SEARCH_HANDS_FREE intents resolve to the stock
     * com.tinnove.aiassistant because of a factory-set addPersistentPreferredActivity record
     * (see Deepal_S05_VoiceAssist README). clearPackagePreferredActivities() is a plain
     * PackageManager API, no special permission documented for it even on a non-privileged
     * caller, but we're android.uid.system now anyway so there's no ambiguity. This only clears
     * the preference record, it does not disable or touch com.tinnove.aiassistant itself - if
     * two apps still match an action afterward, Android shows its own disambiguation chooser
     * instead of silently picking one.
     */
    private void clearAiAssistantPreferred() {
        StringBuilder sb = new StringBuilder("\n=== Clear preferred-activities: com.tinnove.aiassistant ===\n");
        try {
            getPackageManager().clearPackagePreferredActivities("com.tinnove.aiassistant");
            sb.append("-> clearPackagePreferredActivities() returned without throwing.\n")
              .append("   Press the steering wheel button again - if com.deepal.voiceassist now\n")
              .append("   wins (or a chooser appears), this was the blocker.\n");
        } catch (Throwable t) {
            sb.append("-> threw: ").append(t).append("\n");
        }
        append(sb.toString());
        try {
            File f = new File(outDir, "clear_aiassistant_preferred.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write clear_aiassistant_preferred.txt: " + t);
        }
    }

    /**
     * VoiceAssist's VoiceCommandActivity launches fine on the wheel-button wake path now (status
     * bar flicker = the activity actually taking focus), but shows nothing visible and recognizes
     * nothing - most likely because its VoiceOverlay (a SYSTEM_ALERT_WINDOW overlay) silently
     * no-ops without that permission, which is "special access" (not a normal runtime permission
     * - requestPermissions() can't grant it) and could previously only be flipped via the blocked
     * Settings screen or 'adb shell appops set ... allow' (never actually run, since classic
     * cable ADB stayed unauthorized). Since this process is android.uid.system now,
     * Runtime.exec() inherits that UID - running the same 'appops' CLI tool a shell/adb session
     * would run, but from here, with no cable and no USB authorization needed at all.
     */
    private void grantVoiceAssistOverlay() {
        StringBuilder sb = new StringBuilder("\n=== Grant SYSTEM_ALERT_WINDOW to com.deepal.voiceassist (via appops, no ADB) ===\n");
        try {
            Process p = Runtime.getRuntime().exec(new String[]{
                    "appops", "set", "com.deepal.voiceassist", "SYSTEM_ALERT_WINDOW", "allow"});
            String out = readAll(p.getInputStream());
            String err = readAll(p.getErrorStream());
            int code = p.waitFor();
            sb.append("exit=").append(code).append("\n");
            if (!out.isEmpty()) sb.append("stdout:\n").append(out).append("\n");
            if (!err.isEmpty()) sb.append("stderr:\n").append(err).append("\n");
        } catch (Throwable t) {
            sb.append("exec failed: ").append(t).append("\n");
        }

        sb.append("\n-- Verifying with appops get --\n");
        try {
            Process p2 = Runtime.getRuntime().exec(new String[]{
                    "appops", "get", "com.deepal.voiceassist", "SYSTEM_ALERT_WINDOW"});
            String out2 = readAll(p2.getInputStream());
            p2.waitFor();
            sb.append(out2).append("\n");
        } catch (Throwable t) {
            sb.append("verify exec failed: ").append(t).append("\n");
        }

        append(sb.toString());
        try {
            File f = new File(outDir, "grant_voiceassist_overlay.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write grant_voiceassist_overlay.txt: " + t);
        }
    }

    private String readAll(InputStream is) throws Exception {
        java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(is));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) out.append(line).append("\n");
        br.close();
        return out.toString().trim();
    }

    /**
     * Device still shows "unauthorized" after god-mode wrote both key formats to
     * /data/misc/adb/adb_keys, AND no on-screen "Allow USB debugging?" dialog ever appears -
     * not even for a brand-new, never-seen host key, which is the normal AOSP fallback whenever
     * a key isn't already trusted (AdbDebuggingManager.Handler case 5 -> startConfirmationForKey
     * -> android:string/config_customAdbPublicKeyConfirmationComponent, default
     * "com.android.systemui/com.android.systemui.usb.UsbDebuggingActivity" per AOSP source -
     * jadx showed a garbage name "cfTemplateForwardedTime" for this resource when decompiling
     * services.jar alone, almost certainly a resource-id collision from missing framework-res.apk
     * context, not a real OEM rename). This either means that confirmation component itself is
     * disabled/broken on this build, or the live connection attempt never reaches
     * startConfirmationForKey at all (e.g. getFingerprints() on the incoming key returns "" and
     * the Handler silently answers "NO" with no dialog - see case 5 around line 776). This
     * button checks the resource's actual value, the target component's real enabled/exported
     * state via PackageManager (works now that we're android.uid.system), and tries starting it
     * directly with dummy extras to see with our own eyes whether any dialog appears at all -
     * splits "the confirmation UI is broken on this build" from "our pre-auth file write just
     * isn't being read correctly".
     */
    private void checkAdbConfirmationScreen() {
        StringBuilder sb = new StringBuilder("\n=== ADB confirmation screen diagnostic ===\n");
        String componentString = null;
        try {
            android.content.res.Resources sysRes = android.content.res.Resources.getSystem();
            int resId = sysRes.getIdentifier(
                    "config_customAdbPublicKeyConfirmationComponent", "string", "android");
            sb.append("resource id = ").append(resId).append("\n");
            if (resId != 0) {
                componentString = sysRes.getString(resId);
                sb.append("value = '").append(componentString).append("'\n");
            } else {
                sb.append("-> resource not found by name; falling back to the AOSP default name\n");
            }
        } catch (Throwable t) {
            sb.append("resource lookup failed: ").append(t).append("\n");
        }
        if (componentString == null || componentString.trim().isEmpty()) {
            componentString = "com.android.systemui/com.android.systemui.usb.UsbDebuggingActivity";
            sb.append("using AOSP default: '").append(componentString).append("'\n");
        }

        android.content.ComponentName cn = android.content.ComponentName.unflattenFromString(componentString);
        if (cn == null) {
            sb.append("could not parse as ComponentName, aborting.\n");
            append(sb.toString());
            return;
        }

        try {
            android.content.pm.ActivityInfo ai = getPackageManager().getActivityInfo(cn, 0);
            sb.append("ActivityInfo found: enabled=").append(ai.enabled)
              .append(" exported=").append(ai.exported)
              .append(" permission=").append(ai.permission).append("\n");
        } catch (Throwable t) {
            sb.append("getActivityInfo failed: ").append(t).append("\n");
        }

        try {
            int enabledSetting = getPackageManager().getComponentEnabledSetting(cn);
            sb.append("getComponentEnabledSetting = ").append(enabledSetting)
              .append(" (0=DEFAULT, 1=ENABLED, 2=DISABLED, 3=DISABLED_USER, 4=DISABLED_UNTIL_USED)\n");
        } catch (Throwable t) {
            sb.append("getComponentEnabledSetting failed: ").append(t).append("\n");
        }

        sb.append("\nTrying to start it directly with dummy extras - WATCH THE HEAD UNIT SCREEN NOW.\n");
        try {
            Intent intent = new Intent();
            intent.setComponent(cn);
            intent.putExtra("key", "dummy_test_key_from_deepalprobe");
            intent.putExtra("fingerprints", "AA:BB:CC:DD (test, ignore)");
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            sb.append("-> startActivity() returned without throwing.\n");
        } catch (Throwable t) {
            sb.append("-> startActivity() threw: ").append(t).append("\n");
        }

        append(sb.toString());
        new Thread(new Runnable() {
            public void run() {
                // Give the activity a moment to actually start (or crash) before we grab
                // logcat - no on-screen dialog appeared despite startActivity() not throwing,
                // and READ_LOGS/log group access should be implied by android.uid.system, so
                // this is the one way left to see WHY without ADB: a stack trace if it crashed
                // in onCreate (e.g. our dummy "fingerprints" extra not parsing the way it
                // expects), a SecurityException if something re-checks the caller beyond the
                // MANAGE_DEBUGGING permission we already hold, or nothing at all if something
                // outside the activity itself (window/task policy) is suppressing it.
                try { Thread.sleep(1500); } catch (InterruptedException ignored) {}
                StringBuilder lb = new StringBuilder("\n=== logcat since startActivity (UsbDebuggingActivity/AdbDebuggingManager/AndroidRuntime) ===\n");
                try {
                    Process p = Runtime.getRuntime().exec(new String[]{
                            "logcat", "-d", "-t", "400",
                            "UsbDebuggingActivity:*", "AdbDebuggingManager:*", "AndroidRuntime:*",
                            "ActivityTaskManager:*", "*:S"});
                    java.io.BufferedReader br = new java.io.BufferedReader(
                            new java.io.InputStreamReader(p.getInputStream()));
                    String line;
                    int n = 0;
                    while ((line = br.readLine()) != null) {
                        lb.append(line).append("\n");
                        n++;
                    }
                    br.close();
                    p.waitFor();
                    lb.append("(").append(n).append(" lines, exit=").append(p.exitValue()).append(")\n");
                } catch (Throwable t) {
                    lb.append("logcat exec failed: ").append(t).append("\n");
                }
                append(lb.toString());
                try {
                    File f = new File(outDir, "adb_confirmation_screen_check.txt");
                    PrintWriter pw = new PrintWriter(new FileOutputStream(f, true));
                    pw.print(lb.toString());
                    pw.close();
                    append("Appended logcat to adb_confirmation_screen_check.txt");
                } catch (Throwable t) {
                    append("could not append logcat: " + t);
                }
            }
        }).start();
        try {
            File f = new File(outDir, "adb_confirmation_screen_check.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName() + " (logcat appended in a moment)");
        } catch (Throwable t) {
            append("could not write adb_confirmation_screen_check.txt: " + t);
        }
    }

    /**
     * The payoff of the test-key discovery (see CLAUDE.md "Публичный AOSP test-key"): every
     * system-uid APK on this build, including com.android.systemui.apk itself, is signed with
     * the public AOSP "platform" test certificate - whose matching private key is openly
     * published in the AOSP source tree. This APK is now built with
     * android:sharedUserId="android.uid.system" in the manifest and signed with that same
     * recovered key (tools/keys/platform.pk8 + platform.x509.pem) instead of the normal debug
     * keystore - if PackageManager accepts the shared-UID claim, this process runs AS
     * android.uid.system, same as EMode/tinnovecoreservice/systemui, which should mean:
     * WRITE_SECURE_SETTINGS is auto-granted (so Settings.Global.putInt("adb_enabled",1) should
     * succeed where button 8 got SecurityException), and plain Unix file ownership on
     * /data/misc/adb/adb_keys (owned by system:shell per project_adb_usb_auth_blocked memory)
     * should allow a direct write where button 7's SAF-picker attempt got EACCES. The adbkey.pub
     * content below is this machine's own public key (C:\Users\1PaPo\.android\adbkey.pub,
     * harmless to embed - it's the public half) so no file picker/USB-stick round trip is needed
     * for this test. /adb_keys (filesystem root) is tried too but EROFS there is a kernel-level
     * read-only mount, independent of UID - expected to still fail even as system.
     */
    private static final String ADB_PUBLIC_KEY =
            "QAAAAM9am2nRkxqGGzUFf+C+FR95uM02Psgpx9CdbLJSwsUA0UkQkvvOk4keVnl8/vc6HqDZg+7+54KBWSrCSxo6tn4g2tzvlF5Au2dj+4NSkoUtG1dzG2Dv8cw9yUnhgGf89LSiC8jHHHs1AmGLbOMw3dSNM+1FqWp2cnlJUTGHyorOB2B18Cvhf3Ij8CFHYzZDApK50CMZ0S8rdYbg4W7X2Qs9Emiam9MZjX7opKcjX2oSRHzMjnIWkrEY/pGkAdUpbuvnLyzmBB6sgVbNZJ+4Flp4qTWuO5e4WsqlSw3kFeFjxdVqhJc6U6+MYgOCh+Dr4VxwzryTVIqRKFHctQBACwLbei6wcwbAoORKr6FlHJxiYoQ21bkNU0WS/F3RM+tzdgYmoRdbkIktN3wMLYlxpI/U8xCMV5s7VFPNcrgZjSiFwM0dj+SYKYUj/I3sIMns1AsfKGw/7PXg8eUfJZqlc38dJe4u9h9IAzRRtKXODwHfeUG8kmz5Y/1+rlV6Y+Vbqs6eDTQJoodmaZh6cyk3RtnaoJXhvBKo7dDFmSrBCfzmp7TLh9Q0mYza//i4eRgP6JS6QTArOamVCMwNgLbodAq1eYYKcgwKI9OoM1/kb+NneG1qXi+/6ZFyy182V2/0JX4yg44WIl/pM8eUVFCQlIVah6KIfMahxIAa2wdtaqD/waufHgEAAQA= 1PaPoV@DESKTOP-NFDFSTP";

    private void godMode() {
        StringBuilder sb = new StringBuilder("\n=== GOD MODE (platform test-key sharedUserId=android.uid.system) ===\n");
        sb.append("myPid=").append(android.os.Process.myPid())
          .append(" myUid=").append(android.os.Process.myUid()).append("\n");
        try {
            int selfCheck = getPackageManager().checkPermission(
                    "android.permission.WRITE_SECURE_SETTINGS", getPackageName());
            sb.append("self WRITE_SECURE_SETTINGS = ")
              .append(selfCheck == PackageManager.PERMISSION_GRANTED ? "GRANTED" : "denied").append("\n");
        } catch (Throwable t) {
            sb.append("self permission check failed: ").append(t).append("\n");
        }

        sb.append("\n-- Settings.Global.putInt(\"adb_enabled\", 1) --\n");
        try {
            android.provider.Settings.Global.putInt(getContentResolver(), "adb_enabled", 1);
            int now = android.provider.Settings.Global.getInt(getContentResolver(), "adb_enabled", -1);
            sb.append("-> call succeeded. adb_enabled now reads back as ").append(now).append("\n");
        } catch (Throwable t) {
            sb.append("-> threw: ").append(t).append("\n");
        }

        // AdbDebuggingManager$AdbKeyStore.addUserKeysToKeyStore() (services_src, line ~1797)
        // reads /data/misc/adb/adb_keys with in.readLine() and uses the WHOLE line as the
        // mKeyMap key, unlike getSystemKeysFromFile() for /adb_keys which does key.trim() but
        // still keeps the full line. isKeyAuthorized(key) then looks up that exact string. The
        // first god-mode run wrote only the full "<base64> user@host" line (as it appears in
        // adbkey.pub) and still showed "unauthorized" after reboot - most likely because the ADB
        // wire protocol's auth handshake sends only the bare base64 key (no " user@host"
        // comment), so the live lookup key never matches our stored line. Writing both the full
        // line and the bare-key-only line covers either format without needing to guess which
        // one the daemon actually uses.
        String keyOnly = ADB_PUBLIC_KEY.contains(" ")
                ? ADB_PUBLIC_KEY.substring(0, ADB_PUBLIC_KEY.indexOf(' '))
                : ADB_PUBLIC_KEY;

        sb.append("\n-- Writing adbkey.pub (full line + bare-key-only) to adb key files --\n");
        String[] targets = {"/adb_keys", "/data/misc/adb/adb_keys"};
        for (String targetPath : targets) {
            File target = new File(targetPath);
            sb.append(targetPath).append("  exists=").append(target.exists())
              .append(" canRead=").append(target.canRead())
              .append(" canWrite=").append(target.canWrite()).append("\n");
            try {
                FileOutputStream fos = new FileOutputStream(target, true);
                fos.write(("\n" + ADB_PUBLIC_KEY + "\n" + keyOnly + "\n").getBytes("UTF-8"));
                fos.flush();
                fos.close();
                sb.append("  SUCCESS: wrote key to ").append(targetPath).append("\n");
            } catch (Throwable writeErr) {
                sb.append("  WRITE FAILED: ").append(writeErr).append("\n");
            }
        }

        sb.append("\n-- Reading back /data/misc/adb/adb_keys --\n");
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.FileReader("/data/misc/adb/adb_keys"));
            String line;
            int n = 0;
            while ((line = br.readLine()) != null) {
                n++;
                sb.append("  [").append(n).append("] len=").append(line.length())
                  .append(" '").append(line).append("'\n");
            }
            br.close();
        } catch (Throwable t) {
            sb.append("  readback failed: ").append(t).append("\n");
        }
        sb.append("\nIf adb_enabled succeeded and at least one key write succeeded: reboot the\n")
          .append("head unit, then 'adb devices' from the laptop should show it as authorized\n")
          .append("without any on-screen confirmation dialog.\n");

        append(sb.toString());
        try {
            File f = new File(outDir, "god_mode_result.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write god_mode_result.txt: " + t);
        }
    }

    /**
     * PackageManager.checkPermission(perm, pkg) inspects what's ACTUALLY granted to another
     * installed package, regardless of what that package's own manifest requests - unlike
     * reading an APK's manifest (which only shows what it asks for), this is the live runtime
     * answer, and needs no special permission itself to call. Closes the open question from
     * this session's static analysis: com.wtcl.filemanager requests WRITE_SECURE_SETTINGS in
     * its manifest but sits in /system/app (not /system/priv-app), so it's almost certainly not
     * actually granted - signature|privileged permissions only take effect for priv-app installs
     * on the OEM's privapp-permissions allowlist. Also checks the system-UID adayo apps and
     * developeroptions/providers.settings themselves, for completeness.
     */
    private static final String[] GRANT_CHECK_PACKAGES = {
            "com.wtcl.filemanager",
            "com.adayo.app.autotest",
            "com.adayo.app.dynomode",
            "com.adayo.app.emode",
            "com.android.car.developeroptions",
            "com.android.providers.settings",
            "com.wt.tinnovecoreservice",
            "com.wt.vehiclecenter",
    };

    private static final String[] GRANT_CHECK_PERMISSIONS = {
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.MANAGE_DEBUGGING",
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
            "android.permission.WRITE_SETTINGS",
    };

    private void checkGrantedPermissions() {
        StringBuilder sb = new StringBuilder("\n=== Actually-granted permission check (PackageManager.checkPermission) ===\n");
        PackageManager pm = getPackageManager();
        for (String pkg : GRANT_CHECK_PACKAGES) {
            sb.append(pkg).append(":\n");
            for (String perm : GRANT_CHECK_PERMISSIONS) {
                try {
                    int result = pm.checkPermission(perm, pkg);
                    sb.append("  ").append(perm).append(" = ")
                      .append(result == PackageManager.PERMISSION_GRANTED ? "GRANTED" : "denied")
                      .append("\n");
                } catch (Throwable t) {
                    sb.append("  ").append(perm).append(" -> error: ").append(t).append("\n");
                }
            }
        }
        append(sb.toString());
        try {
            File f = new File(outDir, "granted_permissions_check.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write granted_permissions_check.txt: " + t);
        }
    }

    /**
     * Found by decompiling com.android.car.developeroptions.apk and com.android.systemui.apk
     * this session: Developer Options is gated by the standard AOSP pattern - an
     * android:enabled="false" Settings$DevelopmentSettingsDashboardActivity plus a priority=-1
     * DevelopmentSettingsDisabledActivity fallback (just a Toast) on the same
     * android.settings.APPLICATION_DEVELOPMENT_SETTINGS action - not something this OEM build
     * specifically removed. The real unlock is the standard "tap build number 7x" flow
     * (DevelopmentSettingsEnabler.setDevelopmentSettingsEnabled()), never actually tried by hand
     * on this head unit's own Settings UI (only the intent deep-link was tried, which is expected
     * to hit the disabled fallback either way, unlock or not, that's just how AOSP resolves a
     * disabled component). isDevelopmentSettingsEnabled() additionally requires
     * !hasUserRestriction("no_debugging_features") - if that restriction is set, tapping 7x
     * would do nothing even if the screen is reachable, so check it first. Both
     * "development_settings_enabled" and "adb_enabled" are written via Settings.Global.putInt(),
     * which requires WRITE_SECURE_SETTINGS - a signature permission this app doesn't hold - so
     * the writes below are expected to throw SecurityException; this just gets the exact
     * exception on record instead of assuming, and costs nothing if it fails (if it somehow
     * doesn't fail, that's the dev-settings/ADB toggle flipped on, which is the goal anyway).
     */
    private void checkDevSettingsUnlock() {
        StringBuilder sb = new StringBuilder("\n=== Dev settings unlock check ===\n");
        try {
            android.os.UserManager um = (android.os.UserManager) getSystemService(android.os.UserManager.class);
            boolean restricted = um.hasUserRestriction("no_debugging_features");
            sb.append("UserManager.hasUserRestriction(\"no_debugging_features\") = ").append(restricted).append("\n");
            if (restricted) {
                sb.append("-> blocked by device policy even if the UI is reachable and tapped 7x -\n")
                  .append("   a factory/MDM restriction, not just the disabled-activity gate.\n");
            } else {
                sb.append("-> not restricted - tapping the build number 7x in the car's own Settings\n")
                  .append("   UI (if reachable by touch) should work normally.\n");
            }
        } catch (Throwable t) {
            sb.append("hasUserRestriction check failed: ").append(t).append("\n");
        }

        sb.append("\nTrying Settings.Global.putInt(\"development_settings_enabled\", 1) directly:\n");
        try {
            android.provider.Settings.Global.putInt(getContentResolver(), "development_settings_enabled", 1);
            sb.append("-> call returned without throwing (unexpected - dev settings may now be ON).\n");
        } catch (Throwable t) {
            sb.append("-> threw: ").append(t).append("\n");
        }

        sb.append("\nTrying Settings.Global.putInt(\"adb_enabled\", 1) directly:\n");
        try {
            android.provider.Settings.Global.putInt(getContentResolver(), "adb_enabled", 1);
            sb.append("-> call returned without throwing (unexpected - ADB may now be ON, try 'adb devices').\n");
        } catch (Throwable t) {
            sb.append("-> threw: ").append(t).append("\n");
        }

        append(sb.toString());
        try {
            File f = new File(outDir, "dev_settings_check.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write dev_settings_check.txt: " + t);
        }
    }

    /**
     * Deepal_S05_VoiceAssist "Шаг 0": can a normal third-party app reach the Tinnove
     * polymeric_service (the shared Binder behind both confirmed-working window commands and
     * climate/AC commands) via the hidden android.os.ServiceManager.getService() API? Found by
     * decompiling com.wt.tinnovecoreservice.apk's ServiceConnectImpl.getService() this session.
     * Not guessable from code alone - Android's hidden-API policy may block this for a
     * non-privileged app depending on targetSdkVersion. This settles it empirically.
     */
    private void checkPolymericService() {
        StringBuilder sb = new StringBuilder("\n=== polymeric_service reachability (VoiceAssist Step 0) ===\n");
        try {
            Class<?> smCls = Class.forName("android.os.ServiceManager");
            Method getService = smCls.getMethod("getService", String.class);
            Object binderObj = getService.invoke(null, "polymeric_service");
            sb.append("ServiceManager.getService(\"polymeric_service\") reflection call: OK\n");
            if (binderObj == null) {
                sb.append("-> returned null: service not registered under this name, or not visible to us.\n");
            } else {
                android.os.IBinder binder = (android.os.IBinder) binderObj;
                sb.append("-> got an IBinder. isBinderAlive()=").append(binder.isBinderAlive()).append("\n");
                try {
                    String descriptor = binder.getInterfaceDescriptor();
                    sb.append("-> getInterfaceDescriptor() = ").append(descriptor).append("\n");
                    if ("com.tinnove.polymericservice.IPolymericService".equals(descriptor)) {
                        sb.append("-> MATCHES IPolymericService. A real cross-process transact() went through:\n")
                          .append("   this app CAN reach polymeric_service. PolymericServiceClient is viable.\n");
                    } else {
                        sb.append("-> descriptor does not match IPolymericService - got some other service, or a stub.\n");
                    }
                } catch (Throwable t) {
                    sb.append("-> getInterfaceDescriptor() (a real transact() call) failed: ").append(t).append("\n")
                      .append("   got the binder reference but couldn't actually talk to it - likely blocked\n")
                      .append("   at the SELinux/binder level even though the reflection call itself worked.\n");
                }
            }
        } catch (ClassNotFoundException e) {
            sb.append("Class.forName(\"android.os.ServiceManager\") failed: ").append(e).append("\n")
              .append("-> hidden API fully blocked at the classloader level for this app.\n");
        } catch (Throwable t) {
            sb.append("reflection call failed: ").append(t).append("\n")
              .append("(if this is a NoSuchMethodException/SecurityException/InvocationTargetException\n")
              .append(" wrapping one, that's Android's hidden-API policy rejecting this for a\n")
              .append(" non-privileged app - PolymericServiceClient would not be viable, fall back to\n")
              .append(" WidgetBroadcastController-only and find another way for climate.)\n");
        }

        append(sb.toString());
        try {
            File f = new File(outDir, "polymeric_service_check.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write polymeric_service_check.txt: " + t);
        }
    }

    /**
     * Reproduces com.adayo.app.emode.util.StorageUtils.c() exactly (found via decompiling
     * EMode.apk): ro.build.type, then StorageManager.getVolumes() filtered to disk.isUsb(),
     * then checks for safe.txt at that volume's root. Insert a real USB flash drive with
     * safe.txt at its root into the head unit's USB-A port BEFORE pressing this button.
     */
    private void checkUsbDetection() {
        StringBuilder sb = new StringBuilder("\n=== USB disk detection (EMode ADB-gate diagnostic) ===\n");
        try {
            Class<?> spCls = Class.forName("android.os.SystemProperties");
            String buildType = (String) spCls.getMethod("get", String.class).invoke(null, "ro.build.type");
            sb.append("ro.build.type = ").append(buildType).append("\n");
            if (!"user".equals(buildType)) {
                sb.append("-> NOT a 'user' build: EMode's gate would allow ADB unconditionally (file check skipped).\n");
            } else {
                sb.append("-> 'user' build: EMode's gate requires the USB-file check below.\n");
            }
        } catch (Throwable t) {
            sb.append("ro.build.type read failed: ").append(t).append("\n");
        }

        try {
            Object storageManager = getSystemService("storage");
            if (storageManager == null) {
                sb.append("getSystemService(\"storage\") returned null\n");
            } else {
                Method getVolumes = storageManager.getClass().getMethod("getVolumes");
                List<?> volumes = (List<?>) getVolumes.invoke(storageManager);
                sb.append("StorageManager.getVolumes() -> ").append(volumes == null ? "null" : volumes.size() + " volume(s)").append("\n");
                if (volumes != null) {
                    boolean foundUsb = false;
                    for (Object vol : volumes) {
                        String path = "?";
                        String state = "?";
                        boolean isUsb = false;
                        boolean diskNull = true;
                        try {
                            Method getPath = vol.getClass().getMethod("getPath");
                            Object pathFile = getPath.invoke(vol);
                            path = String.valueOf(pathFile);
                        } catch (Throwable ignored) {}
                        try {
                            Method getState = vol.getClass().getMethod("getState");
                            state = String.valueOf(getState.invoke(vol));
                        } catch (Throwable ignored) {}
                        try {
                            Method getDisk = vol.getClass().getMethod("getDisk");
                            Object disk = getDisk.invoke(vol);
                            diskNull = disk == null;
                            if (disk != null) {
                                Method isUsbM = disk.getClass().getMethod("isUsb");
                                isUsb = (Boolean) isUsbM.invoke(disk);
                            }
                        } catch (Throwable ignored) {}
                        sb.append("  volume: path=").append(path)
                                .append(" state=").append(state)
                                .append(" disk=").append(diskNull ? "null" : "present")
                                .append(" disk.isUsb()=").append(isUsb)
                                .append("\n");
                        if (isUsb) {
                            foundUsb = true;
                            if (!"?".equals(path) && !"null".equals(path)) {
                                File safe = new File(path, "safe.txt");
                                sb.append("    -> safe.txt exists at this volume's root: ").append(safe.exists()).append("\n");
                            }
                        }
                    }
                    if (!foundUsb) {
                        sb.append("-> NO volume with disk.isUsb()==true found. This is why EMode's check\n")
                          .append("   fails regardless of the file name/content - StorageUtils.a() returns\n")
                          .append("   null before the safe.txt check even runs. Insert the drive directly\n")
                          .append("   into the head unit's own USB-A port (not an SD slot/hub/adapter) and\n")
                          .append("   retry; if it still shows no disk.isUsb()==true volume, the OEM build\n")
                          .append("   may not expose this drive as a 'USB disk' VolumeInfo at all.\n");
                    }
                }
            }
        } catch (Throwable t) {
            sb.append("getVolumes() reflection failed: ").append(t).append("\n");
        }

        sb.append("\n=== CarPowerManager.getPowerState() (EMode's second ADB gate requires ON=6) ===\n");
        try {
            Class<?> carCls = Class.forName("android.car.Car");
            Object car = carCls.getMethod("createCar", android.content.Context.class)
                    .invoke(null, (Object) this);
            if (car == null) {
                sb.append("Car.createCar() returned null - car service not connected/available to this app.\n");
            } else {
                // Car.POWER_SERVICE is a public static final String constant.
                Object powerServiceName = carCls.getField("POWER_SERVICE").get(null);
                Object carPowerManager = carCls.getMethod("getCarManager", String.class)
                        .invoke(car, powerServiceName);
                if (carPowerManager == null) {
                    sb.append("getCarManager(POWER_SERVICE) returned null.\n");
                } else {
                    Object powerState = carPowerManager.getClass().getMethod("getPowerState").invoke(carPowerManager);
                    sb.append("getPowerState() = ").append(powerState)
                      .append(" (EMode's gate needs exactly 6 = PowerState.ON)\n");
                }
            }
        } catch (Throwable t) {
            sb.append("Car API access failed: ").append(t).append("\n")
              .append("(if this is a SecurityException, a third-party app may not be allowed to read\n")
              .append(" car power state at all - EMode being a /system/app may have privileges this\n")
              .append(" probe does not)\n");
        }

        append(sb.toString());
        try {
            File f = new File(outDir, "usb_detection_check.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write usb_detection_check.txt: " + t);
        }
    }

    /**
     * No ADB/root path has worked so far for authorizing this laptop's USB debugging key on
     * this head unit (unauthorized stays stuck - see project_adb_usb_auth_blocked memory). The
     * one place a regular app process might still read without root is /system itself - on
     * stock AOSP, files under /system are normally world-readable (standard file_contexts
     * labeling + mode bits), even though writing there needs root. If so, we can pull
     * services.jar (where AdbDebuggingManager/UsbDebuggingActivity's logic would live on stock
     * AOSP, and where any OEM patch to it would show up) off the device without ADB at all, by
     * just reading it like any other file. Scans several known AOSP framework dirs rather than
     * hardcoding one exact path, since the dex2oat layout varies by Android version/build.
     */
    private void copyFrameworkJars() {
        append("\n=== Scanning /system/framework, /vendor/framework for readable .jar/.odex/.vdex ===");
        new Thread(new Runnable() {
            public void run() {
                try {
                    doCopyFrameworkJars();
                    append("\n=== DONE. Check /framework_jars and framework_scan_log.txt ===");
                } catch (Throwable t) {
                    append("FATAL: " + t);
                }
            }
        }).start();
    }

    private static final String[] FRAMEWORK_SCAN_DIRS = {
            "/system/framework",
            "/system/framework/oat/arm64",
            "/system/framework/oat/arm",
            "/system_ext/framework",
            "/product/framework",
            "/vendor/framework",
    };

    private void doCopyFrameworkJars() {
        File destDir = new File(outDir, "framework_jars");
        destDir.mkdirs();
        File logFile = new File(outDir, "framework_scan_log.txt");
        PrintWriter log2;
        try {
            log2 = new PrintWriter(new FileOutputStream(logFile));
        } catch (Throwable t) {
            append("could not open log file: " + t);
            return;
        }

        for (String dirPath : FRAMEWORK_SCAN_DIRS) {
            File dir = new File(dirPath);
            String line = dirPath + "  exists=" + dir.exists() + "  canRead=" + dir.canRead();
            append(line);
            log2.println(line);
            if (!dir.exists() || !dir.canRead()) continue;

            File[] files = dir.listFiles();
            if (files == null) {
                line = "  listFiles() returned null (readable but can't list - SELinux?)";
                append(line);
                log2.println(line);
                continue;
            }
            for (File f : files) {
                String name = f.getName();
                boolean interesting = name.endsWith(".jar") || name.endsWith(".odex") || name.endsWith(".vdex") || name.endsWith(".art");
                if (!interesting) continue;
                boolean canRead = f.canRead();
                long len = f.length();
                if (!canRead) {
                    line = "  SKIP (no read) " + name + "  len=" + len;
                    append(line);
                    log2.println(line);
                    continue;
                }
                try {
                    // Flatten into one dir with the source dir folded into the name, since
                    // services.jar could appear under more than one of the scanned dirs.
                    String flatDirName = dirPath.replace('/', '_');
                    File out = new File(destDir, flatDirName + "__" + name);
                    long n = copyFile(f, out);
                    line = "  OK " + name + "  " + n + " bytes -> " + out.getName();
                    append(line);
                    log2.println(line);
                } catch (Throwable t) {
                    line = "  ERROR copying " + name + ": " + t;
                    append(line);
                    log2.println(line);
                }
            }
        }
        log2.close();
        append("Wrote framework_scan_log.txt");
    }

    /**
     * Found by decompiling services.jar's com.android.server.adb.AdbDebuggingManager$AdbKeyStore
     * this session: besides /data/misc/adb/adb_keys (written by the normal on-screen RSA confirm
     * dialog, which never appears on this head unit), there's a SECOND file,
     * "/adb_keys" (filesystem root, not /data), read into AdbKeyStore.mSystemKeys at construction
     * - any key listed there is trusted immediately (mSystemKeys.contains(key) short-circuits
     * the normal confirm-dialog path entirely, see isTrustedKey()/isKeyAuthorized() around line
     * 1930/1944). This is the standard AOSP factory/CI pre-authorization mechanism. Whether an
     * unprivileged app can actually WRITE there (as opposed to just reading /system, which we
     * already proved works) is unknown until tested - this button finds the real USB disk (same
     * disk.isUsb() logic as checkUsbDetection()), reads adbkey.pub from its root, and tries to
     * write it to /adb_keys. mSystemKeys is only read once at AdbKeyStore construction inside
     * system_server, which doesn't restart on its own - a reboot is needed afterward regardless
     * of whether this write succeeds, for it to actually take effect.
     */
    /**
     * canRead=false on the USB volume's adbkey.pub persisted even after lowering targetSdk to
     * 28 (tested on-device) - turns out requestLegacyExternalStorage/low-targetSdk Scoped
     * Storage opt-out is DOCUMENTED to be ignored entirely on Android 11+ (this device is
     * Android 11), it only ever worked on Android 10. MANAGE_EXTERNAL_STORAGE would fix it but
     * needs the same blocked Settings screen as everything else on this build. The one
     * Scoped-Storage-exempt path left is the Storage Access Framework system file picker
     * (ACTION_OPEN_DOCUMENT) - a different system app (DocumentsUI) from com.android.settings,
     * not yet seen to be blocked on this build. Reading via the returned content:// Uri bypasses
     * the File-API restriction entirely; this has nothing to do with writing to /adb_keys
     * afterward (that's plain filesystem permission on the OS root, unrelated to Scoped Storage,
     * not yet actually tested since we never got past reading the source key before).
     */
    private void tryWriteAdbKey() {
        append("\n=== Pick adbkey.pub via system file picker (Scoped Storage workaround) ===");
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        try {
            startActivityForResult(intent, REQUEST_PICK_ADB_KEY);
        } catch (Throwable t) {
            append("Could not launch file picker: " + t);
        }
    }

    private static final int REQUEST_PICK_ADB_KEY = 42;

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_PICK_ADB_KEY) return;
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) {
            append("File picker cancelled or returned nothing.");
            return;
        }
        finishAdbKeyWrite(data.getData());
    }

    // /adb_keys sits on the root partition, confirmed EROFS (kernel-level read-only mount, not
    // an app permission issue - no app, rooted or not without a remount, can write there). The
    // OTHER key file AdbDebuggingManager reads, /data/misc/adb/adb_keys, lives on /data (always
    // read-write at the filesystem level) - worth trying separately since the only remaining
    // question there is ordinary Unix file permissions on that specific path/file, not EROFS.
    private static final String[] ADB_KEY_WRITE_TARGETS = {
            "/adb_keys",
            "/data/misc/adb/adb_keys",
    };

    private void finishAdbKeyWrite(Uri pickedUri) {
        StringBuilder sb = new StringBuilder("\n=== Attempt: write picked key to adb key files ===\n");
        try {
            sb.append("Picked: ").append(pickedUri).append("\n");
            String keyContent;
            try (InputStream is = getContentResolver().openInputStream(pickedUri)) {
                if (is == null) throw new java.io.IOException("openInputStream returned null");
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int r;
                while ((r = is.read(buf)) > 0) baos.write(buf, 0, r);
                keyContent = new String(baos.toByteArray(), "UTF-8").trim();
            }
            sb.append("Read ").append(keyContent.length()).append(" chars via SAF (Scoped Storage bypassed)\n");

            for (String targetPath : ADB_KEY_WRITE_TARGETS) {
                File target = new File(targetPath);
                sb.append(targetPath).append("  exists=").append(target.exists())
                  .append(" canRead=").append(target.canRead())
                  .append(" canWrite=").append(target.canWrite()).append("\n");
                try {
                    FileOutputStream fos = new FileOutputStream(target, true); // append, don't clobber any existing keys
                    fos.write(("\n" + keyContent + "\n").getBytes("UTF-8"));
                    fos.flush();
                    fos.close();
                    sb.append("  SUCCESS: wrote key to ").append(targetPath)
                      .append(". REBOOT the head unit now, then retry adb devices.\n");
                } catch (Throwable writeErr) {
                    sb.append("  WRITE FAILED: ").append(writeErr).append("\n");
                }
            }
        } catch (Throwable t) {
            sb.append("FATAL: ").append(t).append("\n");
        }
        append(sb.toString());
        try {
            File f = new File(outDir, "adb_key_write_attempt.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
            append("Wrote " + f.getName());
        } catch (Throwable t) {
            append("could not write adb_key_write_attempt.txt: " + t);
        }
    }

    private void runFocusedCopy() {
        append("\n=== Copying focused candidate list... ===");
        new Thread(new Runnable() {
            public void run() {
                try {
                    copyFocusedApks();
                    append("\n=== DONE. Check /apks and apk_copy_log.txt ===");
                } catch (Throwable t) {
                    append("FATAL: " + t);
                }
            }
        }).start();
    }

    private void copyFocusedApks() {
        PackageManager pm = getPackageManager();
        File apkDir = new File(outDir, "apks");
        apkDir.mkdirs();
        File logFile = new File(outDir, "apk_copy_log.txt");
        PrintWriter log2;
        try {
            log2 = new PrintWriter(new FileOutputStream(logFile));
        } catch (Throwable t) {
            append("could not open log file: " + t);
            return;
        }

        for (String pkg : FOCUSED_TARGETS) {
            try {
                ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                List<String> srcs = new ArrayList<String>();
                if (ai.sourceDir != null) srcs.add(ai.sourceDir);
                if (ai.splitSourceDirs != null) for (String s : ai.splitSourceDirs) srcs.add(s);
                int idx = 0;
                for (String src : srcs) {
                    File in = new File(src);
                    boolean exists = in.exists();
                    boolean canRead = in.canRead();
                    long len = exists ? in.length() : -1;
                    String name = pkg + (idx == 0 ? "" : ("_split" + idx)) + ".apk";
                    if (!canRead) {
                        String line = "SKIP (no read) " + pkg + "  src=" + src
                                + "  exists=" + exists + "  len=" + len;
                        append(line);
                        log2.println(line);
                        idx++;
                        continue;
                    }
                    File out = new File(apkDir, name);
                    long n = copyFile(in, out);
                    String line = "OK " + pkg + "  " + n + " bytes  -> " + out.getName();
                    append(line);
                    log2.println(line);
                    idx++;
                }
            } catch (PackageManager.NameNotFoundException nnfe) {
                String line = "NOT INSTALLED " + pkg;
                append(line);
                log2.println(line);
            } catch (Throwable t) {
                String line = "ERROR " + pkg + "  " + t;
                append(line);
                log2.println(line);
            }
        }
        log2.close();
        append("Wrote apk_copy_log.txt");
    }

    private void append(final String s) {
        runOnUiThread(new Runnable() {
            public void run() { log.append(s + "\n"); }
        });
    }

    private void testRuntimePermission() {
        append("\n--- Requesting BLUETOOTH_SCAN / BLUETOOTH_CONNECT / ACCESS_FINE_LOCATION ---");
        append("Watch whether a permission dialog appears.");
        try {
            String[] perms;
            if (Build.VERSION.SDK_INT >= 31) {
                perms = new String[]{
                        "android.permission.BLUETOOTH_SCAN",
                        "android.permission.BLUETOOTH_CONNECT",
                        "android.permission.ACCESS_FINE_LOCATION"};
            } else {
                perms = new String[]{"android.permission.ACCESS_FINE_LOCATION"};
            }
            requestPermissions(perms, 1001);
        } catch (Throwable t) {
            append("requestPermissions threw: " + t);
        }
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] res) {
        StringBuilder sb = new StringBuilder("\n--- Permission result ---\n");
        for (int i = 0; i < perms.length; i++) {
            boolean granted = i < res.length && res[i] == PackageManager.PERMISSION_GRANTED;
            sb.append(perms[i]).append(" = ").append(granted ? "GRANTED" : "DENIED").append("\n");
        }
        append(sb.toString());
        try {
            File f = new File(outDir, "permission_test.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(f));
            pw.print(sb.toString());
            pw.close();
        } catch (Throwable ignored) {}
    }

    private void runDumpAndCopy() {
        append("\n=== Working... this can take a minute ===");
        new Thread(new Runnable() {
            public void run() {
                try {
                    dumpPackages();
                    copyApks();
                    append("\n=== DONE. Collect files from the output folder. ===");
                } catch (Throwable t) {
                    append("FATAL: " + t);
                }
            }
        }).start();
    }

    private void dumpPackages() throws Exception {
        PackageManager pm = getPackageManager();
        int flags = PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS
                | PackageManager.GET_PERMISSIONS;
        List<PackageInfo> pkgs = pm.getInstalledPackages(flags);
        append("Installed packages visible: " + pkgs.size());

        File f = new File(outDir, "packages_dump.txt");
        PrintWriter pw = new PrintWriter(new FileOutputStream(f));
        pw.println("# Deepal S05 package dump");
        pw.println("# fingerprint=" + Build.FINGERPRINT);
        pw.println("# total=" + pkgs.size());
        pw.println();

        for (PackageInfo pi : pkgs) {
            try {
                ApplicationInfo ai = pi.applicationInfo;
                boolean system = ai != null && (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean enabled = ai != null && ai.enabled;
                pw.println("=== " + pi.packageName + "  v" + pi.versionName
                        + (system ? "  [SYSTEM]" : "  [USER]")
                        + (enabled ? "" : "  [DISABLED]"));
                if (ai != null && ai.sourceDir != null) pw.println("    apk: " + ai.sourceDir);

                pw.println("  -- exported activities --");
                dumpComponents(pw, pi.activities);
                pw.println("  -- exported services --");
                dumpComponents(pw, pi.services);
                pw.println("  -- exported receivers --");
                dumpComponents(pw, pi.receivers);
                pw.println("  -- providers --");
                if (pi.providers != null) {
                    for (ProviderInfo p : pi.providers) {
                        pw.println("    PROVIDER " + p.name
                                + "  exported=" + p.exported
                                + "  authority=" + p.authority
                                + "  readPerm=" + p.readPermission
                                + "  writePerm=" + p.writePermission);
                    }
                }
                pw.println();
            } catch (Throwable t) {
                pw.println("  ! error on " + pi.packageName + ": " + t);
            }
        }
        pw.close();
        append("Wrote " + f.getName());
    }

    private void dumpComponents(PrintWriter pw, ComponentInfo[] comps) {
        if (comps == null) return;
        for (ComponentInfo c : comps) {
            // Only list exported ones (callable from our app) or those with a permission gate.
            String perm = null;
            if (c instanceof ActivityInfo) perm = ((ActivityInfo) c).permission;
            else if (c instanceof ServiceInfo) perm = ((ServiceInfo) c).permission;
            if (c.exported) {
                pw.println("    EXPORTED " + c.name + "  permission=" + perm);
            }
        }
    }

    private void copyApks() {
        PackageManager pm = getPackageManager();
        File apkDir = new File(outDir, "apks");
        apkDir.mkdirs();

        List<String> targets = new ArrayList<String>();

        // 1) The real launcher, resolved precisely.
        try {
            Intent home = new Intent(Intent.ACTION_MAIN);
            home.addCategory(Intent.CATEGORY_HOME);
            ResolveInfo ri = pm.resolveActivity(home, PackageManager.MATCH_DEFAULT_ONLY);
            if (ri != null && ri.activityInfo != null) {
                targets.add(ri.activityInfo.packageName);
                append("Launcher package: " + ri.activityInfo.packageName);
            }
            List<ResolveInfo> homes = pm.queryIntentActivities(home, 0);
            for (ResolveInfo r : homes) if (r.activityInfo != null) addUnique(targets, r.activityInfo.packageName);
        } catch (Throwable t) { append("launcher resolve error: " + t); }

        // 2) All user apps + keyword-matched system apps.
        try {
            List<PackageInfo> pkgs = pm.getInstalledPackages(0);
            for (PackageInfo pi : pkgs) {
                ApplicationInfo ai = pi.applicationInfo;
                if (ai == null) continue;
                boolean system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                if (!system) { addUnique(targets, pi.packageName); continue; }
                String p = pi.packageName.toLowerCase(Locale.US);
                for (String k : KEYWORDS) {
                    if (p.contains(k)) { addUnique(targets, pi.packageName); break; }
                }
            }
        } catch (Throwable t) { append("enumerate error: " + t); }

        append("APK targets: " + targets.size());
        long total = 0;
        for (String pkg : targets) {
            try {
                ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                List<String> srcs = new ArrayList<String>();
                if (ai.sourceDir != null) srcs.add(ai.sourceDir);
                if (ai.splitSourceDirs != null) for (String s : ai.splitSourceDirs) srcs.add(s);
                int idx = 0;
                for (String src : srcs) {
                    File in = new File(src);
                    if (!in.canRead()) { append("  skip (no read): " + pkg + " " + src); continue; }
                    String name = pkg + (idx == 0 ? "" : ("_split" + idx)) + ".apk";
                    File out = new File(apkDir, name);
                    long n = copyFile(in, out);
                    total += n;
                    idx++;
                }
            } catch (Throwable t) {
                append("  copy error " + pkg + ": " + t);
            }
        }
        append("Copied APKs, total ~" + (total / (1024 * 1024)) + " MB into /apks");
    }

    private void addUnique(List<String> l, String s) { if (s != null && !l.contains(s)) l.add(s); }

    private long copyFile(File in, File out) throws Exception {
        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(out);
        byte[] buf = new byte[65536];
        long total = 0; int r;
        while ((r = fis.read(buf)) > 0) { fos.write(buf, 0, r); total += r; }
        fos.flush(); fos.close(); fis.close();
        return total;
    }
}
