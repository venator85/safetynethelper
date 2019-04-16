package com.scottyab.safetynet;

import android.util.Base64;

import com.google.gson.annotations.SerializedName;

import java.util.Arrays;

/**
 * A statement returned by the Attestation API.
 */
public class AttestationStatement extends JsonWebSignature.Payload {
	/**
	 * Embedded nonce sent as part of the request.
	 */
	@SerializedName("nonce")
	private String nonce;

	/**
	 * Timestamp of the request.
	 */
	@SerializedName("timestampMs")
	private long timestampMs;

	/**
	 * Package name of the APK that submitted this request.
	 */
	@SerializedName("apkPackageName")
	private String apkPackageName;

	/**
	 * Digest of certificate of the APK that submitted this request.
	 */
	@SerializedName("apkCertificateDigestSha256")
	private String[] apkCertificateDigestSha256;

	/**
	 * Digest of the APK that submitted this request.
	 */
	@SerializedName("apkDigestSha256")
	private String apkDigestSha256;

	/**
	 * The device passed CTS and matches a known profile.
	 */
	@SerializedName("ctsProfileMatch")
	private boolean ctsProfileMatch;

	/**
	 * The device has passed a basic integrity test, but the CTS profile could not be verified.
	 */
	@SerializedName("basicIntegrity")
	private boolean basicIntegrity;

	@SerializedName("advice")
	private String advice;

	public byte[] getNonce() {
		return Base64.decode(nonce, Base64.NO_WRAP);
	}

	public long getTimestampMs() {
		return timestampMs;
	}

	public String getApkPackageName() {
		return apkPackageName;
	}

	public String getApkDigestSha256() {
		return apkDigestSha256;
	}

	public String[] getApkCertificateDigestSha256() {
		return apkCertificateDigestSha256;
	}

	public boolean isCtsProfileMatch() {
		return ctsProfileMatch;
	}

	public boolean isBasicIntegrity() {
		return basicIntegrity;
	}

	public String getAdvice() {
		return advice;
	}

	@Override
	public String toString() {
		return "AttestationStatement{" +
				"super=" + super.toString() +
				", nonce='" + nonce + '\'' +
				", timestampMs=" + timestampMs +
				", apkPackageName='" + apkPackageName + '\'' +
				", apkCertificateDigestSha256=" + Arrays.toString(apkCertificateDigestSha256) +
				", apkDigestSha256='" + apkDigestSha256 + '\'' +
				", ctsProfileMatch=" + ctsProfileMatch +
				", basicIntegrity=" + basicIntegrity +
				", advice='" + advice + '\'' +
				'}';
	}
}