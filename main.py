import joblib
import numpy as np


model = joblib.load("rf_classifier.pkl")

"""
Suspicious App Features Signature (row 40 of dataset):

1. SEND_SMS
2. READ_PHONE_STATE
3. TelephonyManager.getLine1Number
4. android.telephony.gsm.SmsManager
5. INTERNET
6. TelephonyManager.getDeviceId
7. HttpPost.init
8. HttpUriRequest
"""

suspicious_apk = [
    0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
]

"""
Benign App Features Signature (row 13282 of dataset):

1. Ljava.net.URLDecoder
2. android.content.pm.Signature
3. READ_PHONE_STATE
4. GET_ACCOUNTS
5. Ljava.lang.Class.getDeclaredField
6. Ljavax.crypto.spec.SecretKeySpec
7. android.intent.action.BOOT_COMPLETED
8. MANAGE_ACCOUNTS
9. android.content.pm.PackageInfo
10. KeySpec
11. TelephonyManager.getLine1Number
12. HttpGet.init
13. SecretKey
14. Ljava.lang.Class.getMethod
15. Ljavax.crypto.Cipher
16. READ_SYNC_SETTINGS
17. AUTHENTICATE_ACCOUNTS
18. TelephonyManager.getSubscriberId
19. INSTALL_PACKAGES
20. Ljava.lang.Object.getClass
21. WRITE_SYNC_SETTINGS
22. Ljava.lang.Class.forName
23. INTERNET
24. android.intent.action.PACKAGE_REPLACED
25. Binder
26. IBinder
27. android.os.IBinder
28. WRITE_APN_SETTINGS
29. android.intent.action.TIME_SET
30. TelephonyManager.getDeviceId
31. android.intent.action.PACKAGE_REMOVED
32. android.intent.action.TIMEZONE_CHANGED
33. WAKE_LOCK
34. RECEIVE_BOOT_COMPLETED
35. RESTART_PACKAGES
36. android.intent.action.PACKAGE_ADDED
37. TelephonyManager.getSimCountryIso
38. ACCESS_NETWORK_STATE
39. HttpPost.init
40. HttpUriRequest
41. GET_TASKS
42. BIND_DEVICE_ADMIN
43. onBind
44. CHANGE_WIFI_STATE
45. READ_CONTACTS
46. ACCESS_WIFI_STATE
47. WRITE_EXTERNAL_STORAGE
"""

benign_apk = [
    1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0
]

# print(len(suspicious_apk)) | Output --> 215
# print(len(benign_apk)) | Output --> 215


# Python list does not have a shape attribute.
# Only objects like NumPy arrays have the shape attribute, which describes their dimensions.
suspicious_apk = np.array(suspicious_apk).reshape(1, -1)
benign_apk = np.array(benign_apk).reshape(1, -1)

# print(suspicious_apk.shape) | Output --> (1, 215)
# print(benign_apk.shape)  | Output --> (1, 215)

# Suspicious --> 1, Benign --> 0
suspicious_apk_prediction = model.predict(suspicious_apk)
benign_apk_prediction = model.predict(benign_apk)

class_mapping = {0: "Benign", 1: "Suspicious"}


suspicious_apk_result = class_mapping[suspicious_apk_prediction[0]]
benign_apk_result = class_mapping[benign_apk_prediction[0]]

# Print results
print(f"Prediction for Suspicious APK: {suspicious_apk_result}")
print(f"Prediction for Benign APK: {benign_apk_result}")
