package com.scottyab.safetynet;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.UiThread;
import android.text.TextUtils;
import android.util.Base64;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.Continuation;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.PAYLOAD_VALIDATION_FAILED;


/**
 * Simple wrapper to request google Play services - SafetyNet test
 * Based on the code samples from https://developer.android.com/google/play/safetynet/start.html
 * <p/>
 * Doesn't handle Google play services errors, just calls error on callback.
 * <p/>
 */
public class SafetyNetHelper {

	private static final String TAG = SafetyNetHelper.class.getSimpleName();
	/**
	 * This is used to validate the payload response from the SafetyNet.API,
	 * if it exceeds this duration, the response is considered invalid.
	 */
	private static long MAX_TIMESTAMP_DURATION = TimeUnit.MINUTES.toMillis(2);

	private final String googleDeviceVerificationApiKey;
	private final SecureRandom secureRandom;
	private final Executor executor;

	//used for local validation of API response payload
	private byte[] requestNonce;
	private long requestTimestamp;

	/**
	 * @param googleDeviceVerificationApiKey used to validate safety net response see https://developer.android.com/google/play/safetynet/start.html#verify-compat-check
	 */
	public SafetyNetHelper(@NonNull String googleDeviceVerificationApiKey) {
		if (TextUtils.isEmpty(googleDeviceVerificationApiKey)) {
			throw new IllegalArgumentException("Google Device Verification Api Key not defined. See https://developer.android.com/google/play/safetynet/start.html#verify-compat-check");
		}
		this.googleDeviceVerificationApiKey = googleDeviceVerificationApiKey;
		secureRandom = new SecureRandom();
		executor = Executors.newSingleThreadExecutor();
	}

	/**
	 * Call the SafetyNet test to check if this device profile /ROM has passed the CTS test
	 *
	 * @param context  used to build and init the GoogleApiClient
	 * @param callback results and error handling
	 */
	@UiThread
	public void requestTest(@NonNull final Context context, @NonNull final SafetyNetWrapperCallback callback) {
		int googlePlayServicesAvailable = GoogleApiAvailability.getInstance()
				.isGooglePlayServicesAvailable(context);
		if (googlePlayServicesAvailable != ConnectionResult.SUCCESS) {
			callback.error(new GooglePlayServicesNotAvailableException(googlePlayServicesAvailable));
			return;
		}

		requestNonce = generateOneTimeRequestNonce();
		requestTimestamp = System.currentTimeMillis();

		SafetyNet.getClient(context)
				.attest(requestNonce, googleDeviceVerificationApiKey)
				.continueWith(executor, new Continuation<SafetyNetApi.AttestationResponse, Result>() {
					@Override
					public Result then(@NonNull Task<SafetyNetApi.AttestationResponse> task) throws Exception {
						final String jwsResult = task.getResult()
								.getJwsResult();

						/*
						 * We perform the response verification on an executor (background thread) since the apk
						 * digest calculation may took a long time if the apk is large, and we will deliver the
						 * final result via a callback anyway, so there is no point in blocking the UI.
						 */

						try {
							OfflineVerifier verifier = OfflineVerifier.parse(jwsResult);
							AttestationStatement response = verifier.getAttestationStatement();

							verifier.verify();

							validatePayload(context, response);

							return new Result(response);

						} catch (SafetyNetVerificationException e) {
							return new Result(e);
						}
					}
				})
				.addOnSuccessListener(new OnSuccessListener<Result>() {
					@Override
					public void onSuccess(Result result) {
						if (result.attestationStatement != null) {
							callback.success(result.attestationStatement);
						} else {
							callback.failure(result.safetyNetVerificationException);
						}
					}
				})
				.addOnFailureListener(new OnFailureListener() {
					@Override
					public void onFailure(@NonNull Exception e) {
						callback.error(e);
					}
				});
	}

	private void validatePayload(Context context, AttestationStatement response) throws SafetyNetVerificationException {
		String packageName = context.getPackageName();
		List<String> apkCertificateDigests = Utils.calcApkCertificateDigests(context, packageName);
		String apkDigest = Utils.calcApkDigest(context);

		if (!Arrays.equals(requestNonce, response.getNonce())) {
			throw new SafetyNetVerificationException(PAYLOAD_VALIDATION_FAILED, "Invalid nonce, expected:" + Base64.encodeToString(requestNonce, Base64.NO_WRAP) + ", received:" + Base64.encodeToString(response.getNonce(), Base64.NO_WRAP));
		}

		if (!packageName.equalsIgnoreCase(response.getApkPackageName())) {
			throw new SafetyNetVerificationException(PAYLOAD_VALIDATION_FAILED, "Invalid packageName, expected:" + packageName + ", received:" + response.getApkPackageName());
		}

		long durationOfReq = response.getTimestampMs() - requestTimestamp;
		if (durationOfReq > MAX_TIMESTAMP_DURATION) {
			throw new SafetyNetVerificationException(PAYLOAD_VALIDATION_FAILED, "Duration calculated from the timestamp of response \"" + durationOfReq + " \" exceeds permitted duration of \"" + MAX_TIMESTAMP_DURATION + "\"");
		}

		if (!Arrays.equals(apkCertificateDigests.toArray(), response.getApkCertificateDigestSha256())) {
			throw new SafetyNetVerificationException(PAYLOAD_VALIDATION_FAILED, "Invalid apkCertificateDigest, expected:" + apkCertificateDigests + ", received:" + Arrays.toString(response.getApkCertificateDigestSha256()));
		}

		if (!apkDigest.equals(response.getApkDigestSha256())) {
			throw new SafetyNetVerificationException(PAYLOAD_VALIDATION_FAILED, "Invalid apkDigest, expected:" + apkDigest + ", received:" + response.getApkDigestSha256());
		}
	}

	private byte[] generateOneTimeRequestNonce() {
		byte[] nonce = new byte[32];
		secureRandom.nextBytes(nonce);
		return nonce;
	}

	/**
	 * Simple interface for handling SafetyNet API response
	 */
	public interface SafetyNetWrapperCallback {
		@UiThread
		void success(AttestationStatement response);

		/**
		 * Called if we were unable to verify the SafetyNet response
		 *
		 * @param e
		 */
		@UiThread
		void failure(SafetyNetVerificationException e);

		/**
		 * Called if we were unable to perform the SafetyNet verification request (e.g. network error)
		 *
		 * @param e
		 */
		@UiThread
		void error(Exception e);
	}

	private static class Result {
		AttestationStatement attestationStatement;
		SafetyNetVerificationException safetyNetVerificationException;

		Result(AttestationStatement attestationStatement) {
			this.attestationStatement = attestationStatement;
		}

		Result(SafetyNetVerificationException safetyNetVerificationException) {
			this.safetyNetVerificationException = safetyNetVerificationException;
		}
	}
}
