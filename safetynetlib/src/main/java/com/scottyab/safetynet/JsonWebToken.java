package com.scottyab.safetynet;

import com.google.gson.annotations.SerializedName;

import java.util.Collections;
import java.util.List;

/**
 * <a href="http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08">JSON Web Token (JWT)</a>.
 *
 * <p>Implementation is not thread-safe.
 *
 * @author Yaniv Inbar
 * @since 1.14 (since 1.7 as com.google.api.client.auth.jsontoken.JsonWebToken)
 */
public class JsonWebToken {

	/**
	 * Header.
	 */
	private final Header header;

	/**
	 * Payload.
	 */
	private final Payload payload;

	/**
	 * @param header  header
	 * @param payload payload
	 */
	public JsonWebToken(Header header, Payload payload) {
		this.header = Preconditions.checkNotNull(header);
		this.payload = Preconditions.checkNotNull(payload);
	}

	/**
	 * Returns the header.
	 *
	 * <p>Overriding is only supported for the purpose of calling the super implementation and
	 * changing the return type, but nothing else.
	 */
	public Header getHeader() {
		return header;
	}

	/**
	 * Returns the payload.
	 *
	 * <p>Overriding is only supported for the purpose of calling the super implementation and
	 * changing the return type, but nothing else.
	 */
	public Payload getPayload() {
		return payload;
	}

	/**
	 * Header as specified in <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08#section-5">JWT Header</a>.
	 */
	public static class Header {

		/**
		 * Type header parameter used to declare the type of this object or {@code null} for none.
		 */
		@SerializedName("typ")
		private String type;

		/**
		 * Content type header parameter used to declare structural information about the JWT or {@code
		 * null} for none.
		 */
		@SerializedName("cty")
		private String contentType;

		/**
		 * Returns the type header parameter used to declare the type of this object or {@code null} for
		 * none.
		 */
		public final String getType() {
			return type;
		}

		/**
		 * Returns the content type header parameter used to declare structural information about the
		 * JWT or {@code null} for none.
		 */
		public final String getContentType() {
			return contentType;
		}
	}

	/**
	 * Payload as specified in <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08#section-4.1">Reserved Claim
	 * Names</a>.
	 */
	public static class Payload {

		/**
		 * Expiration time claim that identifies the expiration time (in seconds) on or after which the
		 * token MUST NOT be accepted for processing or {@code null} for none.
		 */
		@SerializedName("exp")
		private Long expirationTimeSeconds;

		/**
		 * Not before claim that identifies the time (in seconds) before which the token MUST NOT be
		 * accepted for processing or {@code null} for none.
		 */
		@SerializedName("nbf")
		private Long notBeforeTimeSeconds;

		/**
		 * Issued at claim that identifies the time (in seconds) at which the JWT was issued or {@code
		 * null} for none.
		 */
		@SerializedName("iat")
		private Long issuedAtTimeSeconds;

		/**
		 * Issuer claim that identifies the principal that issued the JWT or {@code null} for none.
		 */
		@SerializedName("iss")
		private String issuer;

		/**
		 * Audience claim that identifies the audience that the JWT is intended for (should either be a
		 * {@code String} or a {@code List<String>}) or {@code null} for none.
		 */
		@SerializedName("aud")
		private Object audience;

		/**
		 * JWT ID claim that provides a unique identifier for the JWT or {@code null} for none.
		 */
		@SerializedName("jti")
		private String jwtId;

		/**
		 * Type claim that is used to declare a type for the contents of this JWT Claims Set or {@code
		 * null} for none.
		 */
		@SerializedName("typ")
		private String type;

		/**
		 * Subject claim identifying the principal that is the subject of the JWT or {@code null} for
		 * none.
		 */
		@SerializedName("sub")
		private String subject;

		/**
		 * Returns the expiration time (in seconds) claim that identifies the expiration time on or
		 * after which the token MUST NOT be accepted for processing or {@code null} for none.
		 */
		public final Long getExpirationTimeSeconds() {
			return expirationTimeSeconds;
		}

		/**
		 * Returns the not before claim that identifies the time (in seconds) before which the token
		 * MUST NOT be accepted for processing or {@code null} for none.
		 */
		public final Long getNotBeforeTimeSeconds() {
			return notBeforeTimeSeconds;
		}

		/**
		 * Returns the issued at claim that identifies the time (in seconds) at which the JWT was issued
		 * or {@code null} for none.
		 */
		public final Long getIssuedAtTimeSeconds() {
			return issuedAtTimeSeconds;
		}

		/**
		 * Returns the issuer claim that identifies the principal that issued the JWT or {@code null}
		 * for none.
		 */
		public final String getIssuer() {
			return issuer;
		}

		/**
		 * Returns the audience claim that identifies the audience that the JWT is intended for (should
		 * either be a {@code String} or a {@code List<String>}) or {@code null} for none.
		 */
		public final Object getAudience() {
			return audience;
		}

		/**
		 * Returns the list of audience claim that identifies the audience that the JWT is intended for
		 * or empty for none.
		 */
		@SuppressWarnings("unchecked")
		public final List<String> getAudienceAsList() {
			if (audience == null) {
				return Collections.emptyList();
			}
			if (audience instanceof String) {
				return Collections.singletonList((String) audience);
			}
			return (List<String>) audience;
		}

		/**
		 * Returns the JWT ID claim that provides a unique identifier for the JWT or {@code null} for
		 * none.
		 */
		public final String getJwtId() {
			return jwtId;
		}

		/**
		 * Returns the type claim that is used to declare a type for the contents of this JWT Claims Set
		 * or {@code null} for none.
		 */
		public final String getType() {
			return type;
		}

		/**
		 * Returns the subject claim identifying the principal that is the subject of the JWT or {@code
		 * null} for none.
		 */
		public final String getSubject() {
			return subject;
		}
	}
}
