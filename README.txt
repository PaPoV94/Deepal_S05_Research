DeepalProbe — privileged diagnostic/utility app for your own Deepal S05 head unit
==================================================================================

STATUS: no longer just "read-only recon". Signed with the same platform.pk8 key as the
whole firmware and declares android:sharedUserId="android.uid.system" in its manifest,
so it runs as android.uid.system and gets every signature-level permission the OEM's own
system apps have (WRITE_SECURE_SETTINGS, CHANGE_COMPONENT_ENABLED_STATE, etc.) with no
Settings-screen dialog needed (those are blocked on this firmware anyway). Several
buttons below genuinely change system state - this is not read-only anymore.

Classic ADB over cable now works too (button 18, see below) - for most day-to-day needs
a real `adb shell`/`adb push`/`adb logcat` from a laptop is more convenient than most of
these buttons. They're kept because they document exactly how that was reached, and some
(15/16, the shell runners; 9, the permission check) are still genuinely useful on their
own even with ADB available.

BUILD:
  $env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
  cd DeepalProbe
  .\gradlew.bat assembleDebug

SIGN (platform key, same as the rest of the firmware - DeepalOSresearch/tools/keys/):
  & "C:\Users\1PaPo\AppData\Local\Android\Sdk\build-tools\34.0.0\apksigner.bat" sign `
      --key ..\tools\keys\platform.pk8 --cert ..\tools\keys\platform.x509.pem `
      --out DeepalProbe.apk app\build\outputs\apk\debug\app-debug.apk

INSTALL:
  adb install -r DeepalProbe.apk
  (or copy to a USB stick and use the system Package Installer if ADB isn't up yet -
  first install ever needs a plain install, not -r; a signature change on an existing
  install needs `adb uninstall com.PaPoV.Deepal_S05.probe` first, Android refuses to
  change the signing key on an in-place update)

OUTPUT FOLDER: /sdcard/Android/data/com.PaPoV.Deepal_S05.probe/files/
  (most buttons below write a named .txt there in addition to the on-screen log; the
  internal app-private copy at getFilesDir() is NOT used, everything lands in the
  external files dir above so it survives without needing run-as/root to read it back)

BUTTONS

Recon (safe, non-destructive):
  1) DUMP + COPY APKs - every installed package's exported components + permissions
     -> packages_dump.txt, plus copies climate/car/voice/settings APKs -> apks/*.apk
  2) TEST runtime permission dialog (Bluetooth) - does the normal Android permission
     dialog even appear on this firmware -> permission_test.txt
  3) COPY engineering-menu / power-mgmt candidates only - narrower APK copy
  9) CHECK actually-granted permissions on other system apps - confirms which installed
     packages share the platform signature -> granted_permissions_check.txt

ADB investigation (mostly historical now that button 18 solved it - see project
CLAUDE.md "ADB по кабелю — РЕШЕНО" for the full story of why each of these existed):
  4) CHECK EMode ADB-gate (USB disk + car power state)
  6) COPY /system/framework jars (services.jar etc.)
  7) TRY writing adbkey.pub (from USB) to /adb_keys - superseded by button 18, the real
     blocker turned out to be the OEM's gutted confirmation dialog, not the key file
  8) CHECK dev-settings unlock (restriction + adb_enabled write)
  10) GOD MODE: enable adb_enabled + write adb_keys to /data/misc/adb
  11) CHECK/TRY the stock "Allow USB debugging?" confirmation screen directly - confirmed
      dead end, the OEM's UsbDebuggingActivity is gutted (finish()es itself, never shows
      anything, see CLAUDE.md)
  14) CLEAR preferred-activities for com.tinnove.aiassistant (no ADB)
  16) RUN commands.txt from USB stick (no on-screen typing) - line-by-line shell runner,
      writes progress to both the stick and an internal fallback file as it goes so a
      lost stick mid-run doesn't lose earlier results
  17) SWITCH to adb mode + CAPTURE live key exchange (30s, no stick needed) - the button
      that caught the live logcat proving the dialog never fires

The actual ADB fix:
  18) DIRECTLY AUTHORIZE this laptop's key (bypass the broken dialog) - calls
      IAdbManager.allowDebugging() directly via reflection as android.uid.system,
      exactly what tapping "Allow" in the (non-functional) dialog would have done.
      `adb devices` shows `device` after this, alwaysAllow=true so it should survive
      reconnects for about a week of idle time (Settings.Global
      adb_allowed_connection_time) - if it goes back to `unauthorized` after a long gap,
      just press this again.

Other utilities:
  5) CHECK polymeric_service (hidden ServiceManager API) - confirmed reachable from a
     third-party-privileged process, this is the Binder service VoiceAssist's
     PolymericServiceClient talks to for climate/windows
  12) GRANT SYSTEM_ALERT_WINDOW (no ADB) - obsolete, VoiceAssist's overlay no longer
      needs this permission (switched to a direct TYPE_DRAG system window instead)
  13) READ logcat for VoskEngine/AndroidRuntime - ad-hoc VoiceAssist debugging aid
  15) RUN shell command above (as system, no ADB) - type any shell command into the
      EditText above this button, runs via Runtime.exec() as android.uid.system, output
      to screen + shell_last_output.txt. The same thing classic `adb shell` now gives
      you more conveniently, kept for when ADB is down.

A note on using 15/16/17/18 carefully: these genuinely execute shell commands and flip
system properties as android.uid.system. Nothing here is reversible-by-undo the way a
read-only recon button is - read what a commands.txt actually contains before running it
on button 16, and don't blind-fire 17/18 repeatedly in quick succession (both toggle USB
mode, the sort of thing worth doing deliberately, not in a loop).
