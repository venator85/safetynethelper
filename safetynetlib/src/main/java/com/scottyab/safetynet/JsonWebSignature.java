/*
 * Copyright (c) 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.scottyab.safetynet;

import android.support.annotation.NonNull;
import android.util.Base64;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * <a href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11">JSON Web Signature
 * (JWS)</a>.
 *
 * <p>Sample usage:
 *
 * <pre>
 * public static void printPayload(JsonFactory jsonFactory, String tokenString) throws IOException {
 * JsonWebSignature jws = JsonWebSignature.parse(jsonFactory, tokenString);
 * System.out.println(jws.getPayload());
 * }
 * </pre>
 *
 * <p>Implementation is not thread-safe.
 *
 * @author Yaniv Inbar
 * @since 1.14 (since 1.7 as com.google.api.client.auth.jsontoken.JsonWebSignature)
 */
public class JsonWebSignature extends JsonWebToken {

	/**
	 * Bytes of the signature.
	 */
	private final byte[] signatureBytes;

	/**
	 * Bytes of the signature content.
	 */
	private final byte[] signedContentBytes;

	/**
	 * @param header             header
	 * @param payload            payload
	 * @param signatureBytes     bytes of the signature
	 * @param signedContentBytes bytes of the signature content
	 */
	private JsonWebSignature(
			Header header, Payload payload, byte[] signatureBytes, byte[] signedContentBytes) {
		super(header, payload);
		this.signatureBytes = Preconditions.checkNotNull(signatureBytes);
		this.signedContentBytes = Preconditions.checkNotNull(signedContentBytes);
	}

	private static X509TrustManager getDefaultX509TrustManager() throws GeneralSecurityException {
		TrustManagerFactory factory =
				TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init((KeyStore) null);
		for (TrustManager manager : factory.getTrustManagers()) {
			if (manager instanceof X509TrustManager) {
				return (X509TrustManager) manager;
			}
		}
		return null;
	}

	/**
	 * Returns a new instance of a JWS parser.
	 */
	public static Parser parser(Gson gson) {
		return new Parser(gson);
	}

	@Override
	public Header getHeader() {
		return (Header) super.getHeader();
	}

	/**
	 * Verifies the signature of the content using the certificate chain embedded in the signature.
	 *
	 * <p>Currently only {@code "RS256"} algorithm is verified, but others may be added in the future.
	 * For any other algorithm it returns {@code null}.
	 *
	 * <p>The leaf certificate of the certificate chain must be an SSL server certificate.
	 *
	 * @param trustManager Trust manager used to verify the X509 certificate chain embedded in this
	 *                     message.
	 * @return The signature certificate if the signature could be verified, null otherwise.
	 * @throws GeneralSecurityException
	 * @since 1.19.1.
	 */
	@NonNull
	private X509Certificate verifySignature(X509TrustManager trustManager)
			throws GeneralSecurityException {
		List<String> x509Certificates = getHeader().getX509Certificates();
		if (x509Certificates == null || x509Certificates.isEmpty()) {
			throw new GeneralSecurityException("No certificates found in header");
		}
		String algorithm = getHeader().getAlgorithm();
		Signature signatureAlg;
		if ("RS256".equals(algorithm)) {
			signatureAlg = Signature.getInstance("SHA256withRSA");
		} else {
			throw new GeneralSecurityException("Unsupported algorithm " + algorithm);
		}
		return SecurityUtils.verify(
				signatureAlg, trustManager, x509Certificates, signatureBytes, signedContentBytes);
	}

	/**
	 * Verifies the signature of the content using the certificate chain embedded in the signature.
	 *
	 * <p>Currently only {@code "RS256"} algorithm is verified, but others may be added in the future.
	 * For any other algorithm it returns {@code null}.
	 *
	 * <p>The certificate chain is verified using the system default trust manager.
	 *
	 * <p>The leaf certificate of the certificate chain must be an SSL server certificate.
	 *
	 * @return The signature certificate if the signature could be verified, null otherwise.
	 * @throws GeneralSecurityException
	 * @since 1.19.1.
	 */
	@NonNull
	public final X509Certificate verifySignature() throws GeneralSecurityException {
		X509TrustManager trustManager = getDefaultX509TrustManager();
		return verifySignature(trustManager);
	}

	/**
	 * Header as specified in <a
	 * href="http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11#section-4.1">Reserved
	 * Header Parameter Names</a>.
	 */
	@SuppressWarnings("unused")
	public static class Header extends JsonWebToken.Header {

		/**
		 * Algorithm header parameter that identifies the cryptographic algorithm used to secure the JWS
		 * or {@code null} for none.
		 */
		@SerializedName("alg")
		private String algorithm;

		/**
		 * JSON Web Key URL header parameter that is an absolute URL that refers to a resource for a set
		 * of JSON-encoded public keys, one of which corresponds to the key that was used to digitally
		 * sign the JWS or {@code null} for none.
		 */
		@SerializedName("jku")
		private String jwkUrl;

		/**
		 * JSON Web Key header parameter that is a public key that corresponds to the key used to
		 * digitally sign the JWS or {@code null} for none.
		 */
		@SerializedName("jwk")
		private String jwk;

		/**
		 * Key ID header parameter that is a hint indicating which specific key owned by the signer
		 * should be used to validate the digital signature or {@code null} for none.
		 */
		@SerializedName("kid")
		private String keyId;

		/**
		 * X.509 URL header parameter that is an absolute URL that refers to a resource for the X.509
		 * public key certificate or certificate chain corresponding to the key used to digitally sign
		 * the JWS or {@code null} for none.
		 */
		@SerializedName("x5u")
		private String x509Url;

		/**
		 * X.509 certificate thumbprint header parameter that provides a base64url encoded SHA-1
		 * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate that can be used to
		 * match the certificate or {@code null} for none.
		 */
		@SerializedName("x5t")
		private String x509Thumbprint;

		/**
		 * X.509 certificate chain header parameter contains the X.509 public key certificate or
		 * certificate chain corresponding to the key used to digitally sign the JWS or {@code null} for
		 * none.
		 *
		 * @since 1.19.1.
		 */
		@SerializedName("x5c")
		private List<String> x509Certificates;

		/**
		 * Array listing the header parameter names that define extensions that are used in the JWS
		 * header that MUST be understood and processed or {@code null} for none.
		 */
		@SerializedName("crit")
		private List<String> critical;

		/**
		 * Returns the algorithm header parameter that identifies the cryptographic algorithm used to
		 * secure the JWS or {@code null} for none.
		 */
		public final String getAlgorithm() {
			return algorithm;
		}

		/**
		 * Returns the JSON Web Key URL header parameter that is an absolute URL that refers to a
		 * resource for a set of JSON-encoded public keys, one of which corresponds to the key that was
		 * used to digitally sign the JWS or {@code null} for none.
		 */
		public final String getJwkUrl() {
			return jwkUrl;
		}

		/**
		 * Returns the JSON Web Key header parameter that is a public key that corresponds to the key
		 * used to digitally sign the JWS or {@code null} for none.
		 */
		public final String getJwk() {
			return jwk;
		}

		/**
		 * Returns the key ID header parameter that is a hint indicating which specific key owned by the
		 * signer should be used to validate the digital signature or {@code null} for none.
		 */
		public final String getKeyId() {
			return keyId;
		}

		/**
		 * Returns the X.509 URL header parameter that is an absolute URL that refers to a resource for
		 * the X.509 public key certificate or certificate chain corresponding to the key used to
		 * digitally sign the JWS or {@code null} for none.
		 */
		public final String getX509Url() {
			return x509Url;
		}

		/**
		 * Returns the X.509 certificate thumbprint header parameter that provides a base64url encoded
		 * SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate that can be used
		 * to match the certificate or {@code null} for none.
		 */
		public final String getX509Thumbprint() {
			return x509Thumbprint;
		}

		/**
		 * Returns the X.509 certificate chain header parameter contains the X.509 public key
		 * certificate or corresponding to the key used to digitally sign the JWS or {@code null} for
		 * none.
		 *
		 * <p>@deprecated Since release 1.19.1, replaced by {@link #getX509Certificates()}.
		 */
		@Deprecated
		public final String getX509Certificate() {
			if (x509Certificates == null || x509Certificates.isEmpty()) {
				return null;
			}
			return x509Certificates.get(0);
		}

		/**
		 * Returns the X.509 certificate chain header parameter contains the X.509 public key
		 * certificate or certificate chain corresponding to the key used to digitally sign the JWS or
		 * {@code null} for none.
		 *
		 * @since 1.19.1.
		 */
		public final List<String> getX509Certificates() {
			return x509Certificates;
		}

		/**
		 * Returns the array listing the header parameter names that define extensions that are used in
		 * the JWS header that MUST be understood and processed or {@code null} for none.
		 *
		 * @since 1.16
		 */
		public final List<String> getCritical() {
			return critical;
		}
	}

	/**
	 * JWS parser.
	 *
	 * <p>Implementation is not thread-safe.
	 */
	public static final class Parser {

		private final Gson gson;

		/**
		 * Header class to use for parsing.
		 */
		private Class<? extends Header> headerClass = Header.class;

		/**
		 * Payload class to use for parsing.
		 */
		private Class<? extends Payload> payloadClass = Payload.class;

		public Parser(Gson gson) {
			this.gson = Preconditions.checkNotNull(gson);
		}

		/**
		 * Sets the header class to use for parsing.
		 */
		public Parser setHeaderClass(Class<? extends Header> headerClass) {
			this.headerClass = headerClass;
			return this;
		}

		/**
		 * Sets the payload class to use for parsing.
		 */
		public Parser setPayloadClass(Class<? extends Payload> payloadClass) {
			this.payloadClass = payloadClass;
			return this;
		}

		/**
		 * Parses a JWS token into a parsed {@link JsonWebSignature}.
		 *
		 * @param tokenString JWS token string
		 * @return parsed {@link JsonWebSignature}
		 */
		public JsonWebSignature parse(String tokenString) throws IOException {
			// split on the dots
			int firstDot = tokenString.indexOf('.');
			Preconditions.checkArgument(firstDot != -1);

			byte[] headerBytes = Base64.decode(tokenString.substring(0, firstDot), Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);

			int secondDot = tokenString.indexOf('.', firstDot + 1);
			Preconditions.checkArgument(secondDot != -1);
			Preconditions.checkArgument(tokenString.indexOf('.', secondDot + 1) == -1);

			// decode the bytes
			String payload = tokenString.substring(firstDot + 1, secondDot);
			String signature = tokenString.substring(secondDot + 1);
			String signedContent = tokenString.substring(0, secondDot);

			byte[] payloadBytes = Base64.decode(payload, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
			byte[] signatureBytes = Base64.decode(signature, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
			byte[] signedContentBytes = Utils.getBytes(signedContent);

			String sHeaderBytes = new String(headerBytes, Utils.UTF_8);
			String sPayloadBytes = new String(payloadBytes, Utils.UTF_8);

			// parse the header and payload
			Header header = gson.fromJson(sHeaderBytes, headerClass);
			Preconditions.checkArgument(header.getAlgorithm() != null);
			Payload oPayload = gson.fromJson(sPayloadBytes, payloadClass);
			return new JsonWebSignature(header, oPayload, signatureBytes, signedContentBytes);
		}
	}

}
