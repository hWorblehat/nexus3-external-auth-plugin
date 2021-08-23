package io.github.hWorblehat.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.*;
import io.github.hWorblehat.util.DelegateBuilderBase;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class DynamicJWTVerifier implements JWTVerifier {

	private final @Nullable PublicKeyProvider keyProvider;
	private final @Nullable byte[] hmacSecret;
	private final List<Consumer<Verification>> config;

	private final Map<String, JWTVerifier> verifierCache = new HashMap<>();

	@Override
	public DecodedJWT verify(String s) throws JWTVerificationException {
		return verify(JWT.decode(s));
	}

	@Override
	public DecodedJWT verify(DecodedJWT decodedJWT) throws JWTVerificationException {
		return getVerifier(decodedJWT).verify(decodedJWT);
	}

	private JWTVerifier getVerifier(DecodedJWT jws) throws JWTVerificationException {
		return verifierCache.computeIfAbsent(jws.getAlgorithm(), this::createVerifier);
	}

	private JWTVerifier createVerifier(String algorithm) throws JWTVerificationException {
		Verification builder = JWT.require(createAlgorithm(algorithm));
		for(Consumer<Verification> conf : config) {
			conf.accept(builder);
		}
		return builder.build();
	}

	private Algorithm createAlgorithm(String algorithm) throws JWTVerificationException {
		switch (algorithm.intern()) {
			case "RS256":
				return Algorithm.RSA256(requireRSAKeyProvider());
			case "RS384":
				return Algorithm.RSA384(requireRSAKeyProvider());
			case "RS512":
				return Algorithm.RSA512(requireRSAKeyProvider());
			case "ES256":
				return Algorithm.ECDSA256(requireECDSAKeyProvider());
			case "ES384":
				return Algorithm.ECDSA384(requireECDSAKeyProvider());
			case "ES512":
				return Algorithm.ECDSA512(requireECDSAKeyProvider());
			case "ES256K":
				return Algorithm.ECDSA256K(requireECDSAKeyProvider());
			case "HS256":
				return Algorithm.HMAC256(requireHMACSecret());
			case "HS384":
				return Algorithm.HMAC384(requireHMACSecret());
			case "HS512":
				return Algorithm.HMAC512(requireHMACSecret());
			default:
				throw new JWTVerificationException("Unsupported JWT signature verification algorithm: " + algorithm);
		}
	}

	private byte[] requireHMACSecret() throws JWTVerificationException {
		if(hmacSecret == null) {
			throw new JWTVerificationException("Client secret required for HMAC JWT verification.");
		}
		return hmacSecret;
	}

	private RSAKeyProvider requireRSAKeyProvider() throws JWTVerificationException {
		if(keyProvider == null) {
			throw new JWTVerificationException("Public key provider required for RSA JWT verification.");
		}
		return keyProvider.ofRSA();
	}

	private ECDSAKeyProvider requireECDSAKeyProvider() throws JWTVerificationException {
		if(keyProvider == null) {
			throw new JWTVerificationException("Public key provider required for ECDSA JWT verification.");
		}
		return keyProvider.ofECDSA();
	}

	public static Builder builder() {
		return new BuilderImpl();
	}

	public interface IBuilder<B extends IBuilder<B>> {
		B withKeyProvider(PublicKeyProvider keyProvider);

		B withHMACSecret(byte[] hmacSecret);

		B withIssuers(Collection<String> issuers);

		default B withIssuers(String... issuers) {
			return withIssuers(Arrays.asList(issuers));
		}

		B addIssuer(String issuer);

		B addIssuers(Collection<String> issuers);

		default B addIssuers(String... issuers) {
			return addIssuers(Arrays.asList(issuers));
		}

		B withSubject(String s);

		B withAudiences(Collection<String> audiences);

		default B withAudiences(String... audiences) {
			return withAudiences(Arrays.asList(audiences));
		}

		B addAudience(String audience);

		B addAudiences(Collection<String> audiences);

		default B addAudiences(String... audiences) {
			return addAudiences(Arrays.asList(audiences));
		}

		B acceptLeeway(long l) throws IllegalArgumentException;

		B acceptExpiresAt(long l) throws IllegalArgumentException;

		B acceptNotBefore(long l) throws IllegalArgumentException;

		B acceptIssuedAt(long l) throws IllegalArgumentException;

		B withJWTId(String s);

		B withClaimPresence(String s) throws IllegalArgumentException;

		B withClaim(String s, Boolean aBoolean) throws IllegalArgumentException;

		B withClaim(String s, Integer integer) throws IllegalArgumentException;

		B withClaim(String s, Long aLong) throws IllegalArgumentException;

		B withClaim(String s, Double aDouble) throws IllegalArgumentException;

		B withClaim(String s, String s1) throws IllegalArgumentException;

		B withClaim(String s, Date date) throws IllegalArgumentException;

		B withArrayClaim(String s, String... strings) throws IllegalArgumentException;

		B withArrayClaim(String s, Integer... integers) throws IllegalArgumentException;

		B withArrayClaim(String s, Long... longs) throws IllegalArgumentException;

		B ignoreIssuedAt();
	}

	public interface Builder extends IBuilder<Builder> {
		DynamicJWTVerifier build();
	}

	private static class BuilderImpl implements Builder {
		private @Nullable PublicKeyProvider keyProvider = null;
		private @Nullable byte[] hmacSecret = null;
		private final List<Consumer<Verification>> config = new ArrayList<>();
		private final Set<String> issuers = new HashSet<>();
		private final Set<String> audiences = new HashSet<>();
		
		private Builder addConf(Consumer<Verification> conf) {
			config.add(conf);
			return this;
		}

		@Override
		public Builder withKeyProvider(PublicKeyProvider keyProvider) {
			this.keyProvider = keyProvider;
			return this;
		}

		@Override
		public Builder withHMACSecret(byte[] hmacSecret) {
			this.hmacSecret = hmacSecret;
			return this;
		}
		
		@Override
		public Builder withIssuers(Collection<String> issuers) {
			this.issuers.clear();
			this.issuers.addAll(issuers);
			return this;
		}

		@Override
		public Builder addIssuer(String issuer) {
			issuers.add(requireNonNull(issuer));
			return this;
		}
		
		@Override
		public Builder addIssuers(Collection<String> issuers) {
			this.issuers.addAll(issuers);
			return this;
		}

		@Override
		public Builder withSubject(String s) {
			return addConf(v -> v.withSubject(s));
		}

		@Override
		public Builder withAudiences(Collection<String> audiences) {
			this.audiences.clear();
			this.audiences.addAll(audiences);
			return this;
		}

		@Override
		public Builder addAudience(String audience) {
			audiences.add(requireNonNull(audience));
			return this;
		}

		@Override
		public Builder addAudiences(Collection<String> audiences) {
			this.audiences.addAll(audiences);
			return this;
		}

		@Override
		public Builder acceptLeeway(long l) throws IllegalArgumentException {
			assertPositive(l);
			return addConf(v -> v.acceptLeeway(l));
		}

		@Override
		public Builder acceptExpiresAt(long l) throws IllegalArgumentException {
			assertPositive(l);
			return addConf(v -> v.acceptExpiresAt(l));
		}

		@Override
		public Builder acceptNotBefore(long l) throws IllegalArgumentException {
			assertPositive(l);
			return addConf(v -> v.acceptNotBefore(l));
		}

		@Override
		public Builder acceptIssuedAt(long l) throws IllegalArgumentException {
			assertPositive(l);
			return addConf(v -> v.acceptIssuedAt(l));
		}

		@Override
		public Builder withJWTId(String s) {
			return addConf(v -> v.withJWTId(s));
		}

		@Override
		public Builder withClaimPresence(String s) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaimPresence(s));
		}

		@Override
		public Builder withClaim(String s, Boolean aBoolean) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, aBoolean));
		}

		@Override
		public Builder withClaim(String s, Integer integer) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, integer));
		}

		@Override
		public Builder withClaim(String s, Long aLong) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, aLong));
		}

		@Override
		public Builder withClaim(String s, Double aDouble) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, aDouble));
		}

		@Override
		public Builder withClaim(String s, String s1) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, s1));
		}

		@Override
		public Builder withClaim(String s, Date date) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withClaim(s, date));
		}

		@Override
		public Builder withArrayClaim(String s, String... strings) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withArrayClaim(s, strings));
		}

		@Override
		public Builder withArrayClaim(String s, Integer... integers) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withArrayClaim(s, integers));
		}

		@Override
		public Builder withArrayClaim(String s, Long... longs) throws IllegalArgumentException {
			assertNonNull(s);
			return addConf(v -> v.withArrayClaim(s, longs));
		}

		@Override
		public Builder ignoreIssuedAt() {
			return addConf(Verification::ignoreIssuedAt);
		}

		@Override
		public DynamicJWTVerifier build() {
			if(!issuers.isEmpty()) {
				String[] issuersArray = issuers.toArray(new String[issuers.size()]);
				addConf(v -> v.withIssuer(issuersArray));
			}
			if(!audiences.isEmpty()) {
				String[] audiencesArray = audiences.toArray(new String[audiences.size()]);
				addConf(v -> v.withAudience(audiencesArray));
			}
			return new DynamicJWTVerifier(keyProvider, hmacSecret, config);
		}

		private void assertPositive(long leeway) {
			if (leeway < 0L) {
				throw new IllegalArgumentException("Leeway value can't be negative.");
			}
		}

		private void assertNonNull(String name) {
			if (name == null) {
				throw new IllegalArgumentException("The Custom Claim's name can't be null.");
			}
		}
	}

	public interface DelegatingBuilder<B extends IBuilder<B>> extends IBuilder<B>, DelegateBuilderBase<B> {

		IBuilder<?> getJWTVerifierBuilderDelegate();

		@Override
		default B withKeyProvider(PublicKeyProvider keyProvider) {
			getJWTVerifierBuilderDelegate().withKeyProvider(keyProvider);
			return getThis();
		}

		@Override
		default B withHMACSecret(byte[] hmacSecret) {
			getJWTVerifierBuilderDelegate().withHMACSecret(hmacSecret);
			return getThis();
		}

		@Override
		default B withIssuers(Collection<String> issuers) {
			getJWTVerifierBuilderDelegate().withIssuers(issuers);
			return getThis();
		}

		@Override
		default B addIssuer(String issuer) {
			getJWTVerifierBuilderDelegate().addIssuer(issuer);
			return getThis();
		}

		@Override
		default B addIssuers(Collection<String> issuers) {
			getJWTVerifierBuilderDelegate().addIssuers(issuers);
			return getThis();
		}

		@Override
		default B withSubject(String s) {
			getJWTVerifierBuilderDelegate().withSubject(s);
			return getThis();
		}

		@Override
		default B withAudiences(Collection<String> audiences) {
			getJWTVerifierBuilderDelegate().withAudiences(audiences);
			return getThis();
		}

		@Override
		default B addAudience(String audience) {
			getJWTVerifierBuilderDelegate().addAudience(audience);
			return getThis();
		}

		@Override
		default B addAudiences(Collection<String> audiences) {
			getJWTVerifierBuilderDelegate().addAudiences(audiences);
			return getThis();
		}

		@Override
		default B acceptLeeway(long l) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().acceptLeeway(l);
			return getThis();
		}

		@Override
		default B acceptExpiresAt(long l) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().acceptExpiresAt(l);
			return getThis();
		}

		@Override
		default B acceptNotBefore(long l) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().acceptNotBefore(l);
			return getThis();
		}

		@Override
		default B acceptIssuedAt(long l) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().acceptIssuedAt(l);
			return getThis();
		}

		@Override
		default B withJWTId(String s) {
			getJWTVerifierBuilderDelegate().withJWTId(s);
			return getThis();
		}

		@Override
		default B withClaimPresence(String s) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaimPresence(s);
			return getThis();
		}

		@Override
		default B withClaim(String s, Boolean aBoolean) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, aBoolean);
			return getThis();
		}

		@Override
		default B withClaim(String s, Integer integer) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, integer);
			return getThis();
		}

		@Override
		default B withClaim(String s, Long aLong) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, aLong);
			return getThis();
		}

		@Override
		default B withClaim(String s, Double aDouble) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, aDouble);
			return getThis();
		}

		@Override
		default B withClaim(String s, String s1) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, s1);
			return getThis();
		}

		@Override
		default B withClaim(String s, Date date) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withClaim(s, date);
			return getThis();
		}

		@Override
		default B withArrayClaim(String s, String... strings) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withArrayClaim(s, strings);
			return getThis();
		}

		@Override
		default B withArrayClaim(String s, Integer... integers) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withArrayClaim(s, integers);
			return getThis();
		}

		@Override
		default B withArrayClaim(String s, Long... longs) throws IllegalArgumentException {
			getJWTVerifierBuilderDelegate().withArrayClaim(s, longs);
			return getThis();
		}

		@Override
		default B ignoreIssuedAt() {
			getJWTVerifierBuilderDelegate().ignoreIssuedAt();
			return getThis();
		}
	}

}
