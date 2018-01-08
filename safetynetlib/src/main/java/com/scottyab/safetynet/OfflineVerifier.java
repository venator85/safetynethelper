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
	private final String signedAttestationStatement;

	static OfflineVerifier from(String signedAttestationStatement) throws SafetyNetVerificationException {
		try {
			JsonWebSignature jws = JsonWebSignature.parser(AndroidJsonFactory.getDefaultInstance())
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
			if (cert == null) {
				throw new SafetyNetVerificationException(SIGNATURE_VERIFICATION_FAILED, "Signature verification failed, response:" + signedAttestationStatement, null);
			}
		} catch (GeneralSecurityException e) {
			throw new SafetyNetVerificationException(SIGNATURE_VERIFICATION_FAILED, "Error during cryptographic verification of the JWS signature, response:" + signedAttestationStatement, null, e);
		}

		try {
			// Check that the hostname matches the certificate.
			new DefaultHostnameVerifier().verify("attest.android.com", cert);
		} catch (SSLException e) {
			throw new SafetyNetVerificationException(INVALID_CERTIFICATE_ISSUER, "Certificate isn't issued for the hostname attest.android.com, response:" + signedAttestationStatement, null, e);
		}
	}

}