package com.scottyab.safetynet;

import com.google.gson.Gson;
import com.scottyab.safetynet.internal.cz.msebera.android.httpclient.conn.ssl.DefaultHostnameVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.INVALID_CERTIFICATE_ISSUER;
import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.INVALID_JWT_RESPONSE;
import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.SIGNATURE_VERIFICATION_FAILED;

class OfflineVerifier {

	private final JsonWebSignature jws;
	private final String signedAttestationStatement;

	static OfflineVerifier from(String signedAttestationStatement) throws SafetyNetVerificationException {
		try {
			JsonWebSignature jws = JsonWebSignature.parser(new Gson())
					.setPayloadClass(AttestationStatement.class)
					.parse(signedAttestationStatement);
			return new OfflineVerifier(signedAttestationStatement, jws);
		} catch (IOException e) {
			throw new SafetyNetVerificationException(INVALID_JWT_RESPONSE, "AttestationStatement is not valid JWS format: '" + signedAttestationStatement + "'", null, e);
		}
	}

	private OfflineVerifier(String signedAttestationStatement, JsonWebSignature jws) {
		this.signedAttestationStatement = signedAttestationStatement;
		this.jws = jws;
	}

	AttestationStatement getAttestationStatement() {
		return (AttestationStatement) jws.getPayload();
	}

	void verify() throws SafetyNetVerificationException {
		// Verify the signature of the JWS and retrieve the signature certificate.
		X509Certificate cert;
		try {
			cert = jws.verifySignature();
		} catch (GeneralSecurityException e) {
			throw new SafetyNetVerificationException(SIGNATURE_VERIFICATION_FAILED, "Signature verification failed, response: " + signedAttestationStatement + "; " + e.getMessage(), null, e);
		}

		try {
			// Check that the hostname matches the certificate.
			new DefaultHostnameVerifier().verify("attest.android.com", cert);
		} catch (SSLException e) {
			throw new SafetyNetVerificationException(INVALID_CERTIFICATE_ISSUER, "Certificate isn't issued for the hostname attest.android.com, response:" + signedAttestationStatement, null, e);
		}
	}

}