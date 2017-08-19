SafetyNet `attest()` Helper
================

SafetyNet Helper wraps the Google Play Services SafetyNet.API and verifies Safety Net API response with the [Android Device Verification API](https://developer.android.com/google/play/safetynet/start.html#verify-compat-check). The SafetyNet.API analyses the device your app is running on to test its software/hardware configuration matches that of a device that has passed the Android Compatibility Test Suite (CTS). Note this is a client only validation, it's recommended to include [server side validation]().

*Rooted* devices seem to cause `ctsProfileMatch=false`.

**Recommend reading the developers guide to getting started with [SafetyNet](https://developer.android.com/google/play/safetynet/start.html)**

![](./sample/src/main/res/mipmap-xxhdpi/ic_launcher.png)

Extract from Android [SafetyNet API doc](https://developer.android.com/google/play/safetynet/index.html)

*Check if your app is running on a device that matches a device model that has passed Android compatibility testing. This analysis can help you determine if your app will work as expected on the device where it is installed. The service evaluates both software and hardware characteristics of the device, and may use hardware roots of trust, when available.*

*Since this library release Google has created an [Safety Net Sample](https://github.com/googlesamples/android-play-safetynet/tree/master/android/SafetyNetSample)

## Features

* Calls Google Play Services SafetyNet test
* Local verification of request and response
* Asynchronous design to avoid blocking the main thread during heavy local operations (e.g. apk digest calculation)

## Requires / Dependencies

* Google Play services 7+ (specifically the SafetyNet API 'com.google.android.gms:play-services-safetynet:10.0.1')
* Requires Internet permission
* Google API key for the [Android Device Verification API](https://developer.android.com/training/safetynet/index.html#verify-compat-check)

## How to use

You'll need to get a **API key** from the Google developer console to allow you to verify with the Android Device Verification API (in the sample project this is set via a BuildConfig field to keep my api key out of GitHub)

```java
final SafetyNetHelper safetyNetHelper = new SafetyNetHelper(API_KEY);

safetyNetHelper.requestTest(this, new SafetyNetHelper.SafetyNetWrapperCallback() {
    @UiThread
    @Override
    public void success(AttestationStatement response) {
        if (response.isCtsProfileMatch()) {
            //profile of the device running your app matches the profile of a device that has passed Android compatibility testing.
        else if (response.isBasicIntegrity()) {
            //then the device running your app likely wasn't tampered with, but the device has not necessarily passed Android compatibility testing.
        } else {
            //handle fail, maybe warn user device is unsupported or in compromised state? (this is up to you!). response.getAdvice() contains an advice on how to restore the device to a sane state.
        }
    }

    @UiThread
    @Override
    public void failure(SafetyNetVerificationException e) {
        // we were unable to validate the server response, the exception contains an errorCode with more details. This may happen if the response was tampered somehow.
    }

    @UiThread
    @Override
    public void error(Exception e) {
        // we were unable to perform the attest request towards Google, maybe because a network error. The exception may provide more details.
    }
});
```

### Add as dependency

This library is available from JCenter.

```gradle
dependencies {
    compile 'eu.alessiobianchi:safetynethelper:0.3.0'
}
```

## Sample App

The sample app illustrates the helper library in practice. Test your own devices today. 

<img width="270" src="./art/sample_req_pass_cts_pass.png">
<br>
<img width="270" src="./art/sample_req_pass_cts_fail.png">
<img width="270" src="./art/sample_req_pass_validation_fail.png">

## Credits

Heavily based on Scott Alexander-Bown's [safetynethelper](https://github.com/scottyab/safetynethelper).

## Licence

	Copyright (c) 2017 Alessio Bianchi

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
