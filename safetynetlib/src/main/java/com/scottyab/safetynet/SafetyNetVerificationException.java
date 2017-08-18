package com.scottyab.safetynet;

public class SafetyNetVerificationException extends Exception {

	private final ErrorCode code;

	public SafetyNetVerificationException(ErrorCode code, String message) {
		super(message);
		this.code = code;
	}

	public SafetyNetVerificationException(ErrorCode code, String message, Throwable cause) {
		super(message, cause);
		this.code = code;
	}

	public ErrorCode getErrorCode() {
		return code;
	}

	public enum ErrorCode {
		INVALID_JWT_RESPONSE,
		SIGNATURE_VERIFICATION_FAILED,
		INVALID_CERTIFICATE_ISSUER,
		PAYLOAD_VALIDATION_FAILED
	}

}
