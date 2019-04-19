package com.scottyab.safetynet;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build.VERSION;
import android.support.annotation.NonNull;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.X509TrustManager;

/**
 * Utilities related to Java security.
 *
 * @author Yaniv Inbar
 * @since 1.14
 */
final class SecurityUtils {

	private SecurityUtils() {
	}

	/**
	 * Verifies the signature of signed content based on a public key.
	 *
	 * @param signatureAlgorithm signature algorithm
	 * @param publicKey          public key
	 * @param signatureBytes     signature bytes
	 * @param contentBytes       content bytes
	 * @return whether the signature was verified
	 */
	static boolean verify(
			Signature signatureAlgorithm, PublicKey publicKey, byte[] signatureBytes, byte[] contentBytes)
			throws InvalidKeyException, SignatureException {
		signatureAlgorithm.initVerify(publicKey);
		signatureAlgorithm.update(contentBytes);
		// SignatureException may be thrown if we are tring the wrong key.
		return signatureAlgorithm.verify(signatureBytes);
	}

	/**
	 * Verifies the signature of signed content based on a certificate chain.
	 *
	 * @param signatureAlgorithm signature algorithm
	 * @param trustManager       trust manager used to verify the certificate chain
	 * @param certChainBase64    Certificate chain used for verification. The certificates must be base64
	 *                           encoded DER, the leaf certificate must be the first element.
	 * @param signatureBytes     signature bytes
	 * @param contentBytes       content bytes
	 * @return The signature certificate if the signature could be verified, null otherwise.
	 * @since 1.19.1.
	 */
	@NonNull
	static X509Certificate verify(
			Signature signatureAlgorithm,
			X509TrustManager trustManager,
			List<String> certChainBase64,
			byte[] signatureBytes,
			byte[] contentBytes)
			throws GeneralSecurityException {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate[] certificates = new X509Certificate[certChainBase64.size()];
		int currentCert = 0;
		for (String certBase64 : certChainBase64) {
			byte[] certDer = Base64.decode(certBase64, Base64.NO_WRAP);
			ByteArrayInputStream bis = new ByteArrayInputStream(certDer);
			Certificate cert = certificateFactory.generateCertificate(bis);
			if (!(cert instanceof X509Certificate)) {
				throw new GeneralSecurityException("Unsupported certificate type " + cert);
			}
			certificates[currentCert++] = (X509Certificate) cert;
		}

		if (VERSION.SDK_INT >= 17) {
			X509TrustManagerExtensions tme = new X509TrustManagerExtensions(trustManager);
			tme.checkServerTrusted(certificates, "RSA", "attest.android.com");
		} else {
			trustManager.checkServerTrusted(certificates, "RSA");
		}

		PublicKey pubKey = certificates[0].getPublicKey();
		if (verify(signatureAlgorithm, pubKey, signatureBytes, contentBytes)) {
			return certificates[0];
		}
		throw new SignatureException("Verification failed");
	}

}
