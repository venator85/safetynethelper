package com.scottyab.safetynet;

import android.support.annotation.Nullable;

public class SafetyNetVerificationException extends Exception {

	private final ErrorCode code;
	private final AttestationStatement response;

	public SafetyNetVerificationException(ErrorCode code, String message, AttestationStatement response) {
		super(message);
		this.code = code;
		this.response = response;
	}

	public SafetyNetVerificationException(ErrorCode code, String message, AttestationStatement response, Throwable cause) {
		super(message, cause);
		this.code = code;
		this.response = response;
	}

	public ErrorCode getErrorCode() {
		return code;
	}

	@Nullable
	public AttestationStatement getResponse() {
		return response;
	}

	public enum ErrorCode {
		INVALID_JWT_RESPONSE,
		SIGNATURE_VERIFICATION_FAILED,
		INVALID_CERTIFICATE_ISSUER,
		PAYLOAD_VALIDATION_FAILED
	}

}
