import os
from androguard.misc import AnalyzeAPK
import joblib
import numpy as np

def extract_permissions(apk):
    """
    Extract permissions from the APK file.

    Args:
        apk: APK object returned by AnalyzeAPK.

    Returns:
        list: List of permissions extracted.
    """
    permissions = apk.get_permissions()
    return [perm.replace("android.permission.", "") for perm in permissions]

def extract_api_calls(analysis):
    """
    Extract API calls from the APK analysis.

    Args:
        analysis: Analysis object returned by AnalyzeAPK.

    Returns:
        list: List of API calls.
    """
    api_calls = set()
    for method in analysis.get_methods():
        if method.is_external():
            api_calls.add(method.name)
    return list(api_calls)

def extract_intents(apk):
    """
    Extract intents from the APK file.

    Args:
        apk: APK object returned by AnalyzeAPK.

    Returns:
        list: List of intents.
    """
    intents = set()
    for activity in apk.get_activities():
        intent_filters = apk.get_intent_filters("activity", activity)
        if intent_filters and "action" in intent_filters:
            intents.update(intent_filters["action"])
    return list(intents)

def match_features(predefined_features, extracted_features):
    """
    Matches predefined features against extracted features and returns a binary list.

    Args:
        predefined_features (list): List of predefined features (215 features).
        extracted_features (list): List of features extracted from the APK.

    Returns:
        list: A binary list of 1s and 0s indicating the presence of features.
    """
    feature_vector = []
    for feature in predefined_features:
        if feature in extracted_features:
            feature_vector.append(1)  # Exact match
        else:
            # Check for partial match
            partial_match = any(feature in ext_feature or ext_feature in feature for ext_feature in extracted_features)
            if partial_match:
                feature_vector.append(1)
            else:
                feature_vector.append(0)  # No match
    return feature_vector

def main():
    apk_path = "whatsapp.apk"  # Replace with the actual path of your APK file

    if os.path.exists(apk_path):
        apk, dex, analysis = AnalyzeAPK(apk_path)

        # Step 1: Extract features
        permissions = extract_permissions(apk)
        api_calls = extract_api_calls(analysis)
        intents = extract_intents(apk)

        # Combine extracted features
        extracted_features = permissions + api_calls + intents

        # Step 2: Define predefined features (215 features)
        predefined_features = [
    "transact", "onServiceConnected", "bindService", "attachInterface", "ServiceConnection", "android.os.Binder",
    "SEND_SMS", "Ljava.lang.Class.getCanonicalName", "Ljava.lang.Class.getMethods", "Ljava.lang.Class.cast",
    "Ljava.net.URLDecoder", "android.content.pm.Signature", "android.telephony.SmsManager", "READ_PHONE_STATE",
    "getBinder", "ClassLoader", "Landroid.content.Context.registerReceiver", "Ljava.lang.Class.getField",
    "Landroid.content.Context.unregisterReceiver", "GET_ACCOUNTS", "RECEIVE_SMS", "Ljava.lang.Class.getDeclaredField",
    "READ_SMS", "getCallingUid", "Ljavax.crypto.spec.SecretKeySpec", "android.intent.action.BOOT_COMPLETED",
    "USE_CREDENTIALS", "MANAGE_ACCOUNTS", "android.content.pm.PackageInfo", "KeySpec",
    "TelephonyManager.getLine1Number", "DexClassLoader", "HttpGet.init", "SecretKey", "Ljava.lang.Class.getMethod",
    "System.loadLibrary", "android.intent.action.SEND", "Ljavax.crypto.Cipher", "WRITE_SMS", "READ_SYNC_SETTINGS",
    "AUTHENTICATE_ACCOUNTS", "android.telephony.gsm.SmsManager", "WRITE_HISTORY_BOOKMARKS",
    "TelephonyManager.getSubscriberId", "mount", "INSTALL_PACKAGES", "Runtime.getRuntime", "CAMERA",
    "Ljava.lang.Object.getClass", "WRITE_SYNC_SETTINGS", "READ_HISTORY_BOOKMARKS", "Ljava.lang.Class.forName",
    "INTERNET", "android.intent.action.PACKAGE_REPLACED", "Binder", "android.intent.action.SEND_MULTIPLE",
    "RECORD_AUDIO", "IBinder", "android.os.IBinder", "createSubprocess", "NFC", "ACCESS_LOCATION_EXTRA_COMMANDS",
    "URLClassLoader", "WRITE_APN_SETTINGS", "abortBroadcast", "BIND_REMOTEVIEWS", "android.intent.action.TIME_SET",
    "READ_PROFILE", "TelephonyManager.getDeviceId", "MODIFY_AUDIO_SETTINGS", "getCallingPid", "READ_SYNC_STATS",
    "BROADCAST_STICKY", "android.intent.action.PACKAGE_REMOVED", "android.intent.action.TIMEZONE_CHANGED",
    "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "RESTART_PACKAGES", "Ljava.lang.Class.getPackage", "chmod",
    "Ljava.lang.Class.getDeclaredClasses", "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.intent.action.PACKAGE_ADDED", "PathClassLoader", "TelephonyManager.getSimSerialNumber", "Runtime.load",
    "TelephonyManager.getCallState", "BLUETOOTH", "READ_CALENDAR", "READ_CALL_LOG", "SUBSCRIBED_FEEDS_WRITE",
    "READ_EXTERNAL_STORAGE", "TelephonyManager.getSimCountryIso", "sendMultipartTextMessage", "PackageInstaller",
    "VIBRATE", "remount", "android.intent.action.ACTION_SHUTDOWN", "sendDataMessage", "ACCESS_NETWORK_STATE", "chown",
    "HttpPost.init", "Ljava.lang.Class.getClasses", "SUBSCRIBED_FEEDS_READ", "TelephonyManager.isNetworkRoaming",
    "CHANGE_WIFI_MULTICAST_STATE", "WRITE_CALENDAR", "android.intent.action.PACKAGE_DATA_CLEARED", "MASTER_CLEAR",
    "HttpUriRequest", "UPDATE_DEVICE_STATS", "WRITE_CALL_LOG", "DELETE_PACKAGES", "GET_TASKS", "GLOBAL_SEARCH",
    "DELETE_CACHE_FILES", "WRITE_USER_DICTIONARY", "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.NEW_OUTGOING_CALL", "REORDER_TASKS", "WRITE_PROFILE", "SET_WALLPAPER",
    "BIND_INPUT_METHOD", "divideMessage", "READ_SOCIAL_STREAM", "READ_USER_DICTIONARY", "PROCESS_OUTGOING_CALLS",
    "CALL_PRIVILEGED", "Runtime.exec", "BIND_WALLPAPER", "RECEIVE_WAP_PUSH", "DUMP", "BATTERY_STATS",
    "ACCESS_COARSE_LOCATION", "SET_TIME", "android.intent.action.SENDTO", "WRITE_SOCIAL_STREAM", "WRITE_SETTINGS",
    "REBOOT", "BLUETOOTH_ADMIN", "TelephonyManager.getNetworkOperator", "/system/bin", "MessengerService",
    "BIND_DEVICE_ADMIN", "WRITE_GSERVICES", "IRemoteService", "KILL_BACKGROUND_PROCESSES", "SET_ALARM",
    "ACCOUNT_MANAGER", "/system/app", "android.intent.action.CALL", "STATUS_BAR", "TelephonyManager.getSimOperator",
    "PERSISTENT_ACTIVITY", "CHANGE_NETWORK_STATE", "onBind", "Process.start", "android.intent.action.SCREEN_ON",
    "Context.bindService", "RECEIVE_MMS", "SET_TIME_ZONE", "android.intent.action.BATTERY_OKAY",
    "CONTROL_LOCATION_UPDATES", "BROADCAST_WAP_PUSH", "BIND_ACCESSIBILITY_SERVICE", "ADD_VOICEMAIL", "CALL_PHONE",
    "ProcessBuilder", "BIND_APPWIDGET", "FLASHLIGHT", "READ_LOGS", "Ljava.lang.Class.getResource", "defineClass",
    "SET_PROCESS_LIMIT", "android.intent.action.PACKAGE_RESTARTED", "MOUNT_UNMOUNT_FILESYSTEMS",
    "BIND_TEXT_SERVICE", "INSTALL_LOCATION_PROVIDER", "android.intent.action.CALL_BUTTON",
    "android.intent.action.SCREEN_OFF", "findClass", "SYSTEM_ALERT_WINDOW", "MOUNT_FORMAT_FILESYSTEMS",
    "CHANGE_CONFIGURATION", "CLEAR_APP_USER_DATA", "intent.action.RUN", "android.intent.action.SET_WALLPAPER",
    "CHANGE_WIFI_STATE", "READ_FRAME_BUFFER", "ACCESS_SURFACE_FLINGER", "Runtime.loadLibrary", "BROADCAST_SMS",
    "EXPAND_STATUS_BAR", "INTERNAL_SYSTEM_WINDOW", "android.intent.action.BATTERY_LOW", "SET_ACTIVITY_WATCHER",
    "WRITE_CONTACTS", "android.intent.action.ACTION_POWER_CONNECTED", "BIND_VPN_SERVICE", "DISABLE_KEYGUARD",
    "ACCESS_MOCK_LOCATION", "GET_PACKAGE_SIZE", "MODIFY_PHONE_STATE", "CHANGE_COMPONENT_ENABLED_STATE",
    "CLEAR_APP_CACHE", "SET_ORIENTATION", "READ_CONTACTS", "DEVICE_POWER", "HARDWARE_TEST", "ACCESS_WIFI_STATE",
    "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "SET_WALLPAPER_HINTS", "SET_PREFERRED_APPLICATIONS",
    "WRITE_SECURE_SETTINGS"
]


        # Step 3: Match predefined features with extracted features
        feature_vector = match_features(predefined_features, extracted_features)
        print(len(feature_vector))
        feature_vector = np.array(feature_vector).reshape(1, -1)

        model = joblib.load("rf_classifier.pkl")

        class_mapping = {0: "Benign", 1: "Suspicious"}

        prediction = model.predict(feature_vector)
        print(f"Prediction for {apk_path}: {class_mapping[prediction[0]]}")



        # Step 4: Print the binary feature vector
        # print("Predefined Features (Total: {}):".format(len(predefined_features)))
        # print(predefined_features)
        # print("\nExtracted Features (Total: {}):".format(len(extracted_features)))
        # print(extracted_features)
        # print("\nFeature Vector (Length = {}):".format(len(feature_vector)))
        # print(feature_vector)

    else:
        print(f"Error: {apk_path} not found.")

if __name__ == "__main__":
    main()
