package com.scottyab.safetynet;/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import com.google.api.client.extensions.android.json.AndroidJsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

import cz.msebera.android.httpclient.conn.ssl.DefaultHostnameVerifier;

import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.INVALID_CERTIFICATE_ISSUER;
import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.INVALID_JWT_RESPONSE;
import static com.scottyab.safetynet.SafetyNetVerificationException.ErrorCode.SIGNATURE_VERIFICATION_FAILED;

class OfflineVerifier {

	private final JsonWebSignature jws;

	private OfflineVerifier(JsonWebSignature jws) {
		this.jws = jws;
	}

	static OfflineVerifier parse(String signedAttestationStatment) throws SafetyNetVerificationException {
		try {
			JsonWebSignature jws = JsonWebSignature.parser(AndroidJsonFactory.getDefaultInstance())
					.setPayloadClass(AttestationStatement.class)
					.parse(signedAttestationStatment);
			return new OfflineVerifier(jws);
		} catch (IOException e) {
			throw new SafetyNetVerificationException(INVALID_JWT_RESPONSE, "AttestationStatment is not valid JWS format", e);
		}
	}

	JsonWebToken.Header getJwtHeader() {
		return jws.getHeader();
	}

	AttestationStatement getAttestationStatement() {
		return (AttestationStatement) jws.getPayload();
	}

	void verify() throws SafetyNetVerificationException {
		// Verify the signature of the JWS and retrieve the signature certificate.
		X509Certificate cert;
		try {
			cert = jws.verifySignature();
			if (cert == null) {
				throw new SafetyNetVerificationException(SIGNATURE_VERIFICATION_FAILED, "Signature verification failed");
			}
		} catch (GeneralSecurityException e) {
			throw new SafetyNetVerificationException(SIGNATURE_VERIFICATION_FAILED, "Error during cryptographic verification of the JWS signature");
		}

		// Verify the hostname of the certificate.
		if (!verifyHostname("attest.android.com", cert)) {
			throw new SafetyNetVerificationException(INVALID_CERTIFICATE_ISSUER, "Certificate isn't issued for the hostname attest.android.com");
		}
	}

	/**
	 * Verifies that the certificate matches the specified hostname.
	 * Uses the {@link DefaultHostnameVerifier} from the Apache HttpClient library
	 * to confirm that the hostname matches the certificate.
	 *
	 * @param hostname
	 * @param leafCert
	 * @return
	 */
	private boolean verifyHostname(String hostname, X509Certificate leafCert) {
		try {
			// Check that the hostname matches the certificate. This method throws an exception if
			// the cert could not be verified.
			new DefaultHostnameVerifier().verify(hostname, leafCert);
			return true;
		} catch (SSLException e) {
			e.printStackTrace();
		}
		return false;
	}

}