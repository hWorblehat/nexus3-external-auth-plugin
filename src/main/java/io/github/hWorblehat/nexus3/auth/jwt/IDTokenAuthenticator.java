package io.github.hWorblehat.nexus3.auth.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.hWorblehat.nexus3.auth.external.ExternalAuthenticator;
import io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal;
import io.github.hWorblehat.nexus3.auth.jwt.CachingIDTokenAuthHelper.UserData;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class IDTokenAuthenticator extends AbstractIDTokenUserSource<UserData> implements ExternalAuthenticator {
	private static final Logger LOGGER = LoggerFactory.getLogger(IDTokenAuthenticator.class);

	private IDTokenAuthenticator(String issuer, CachingIDTokenAuthHelper<UserData> idTokenCache) {
		super(issuer, idTokenCache);
	}

	@Override
	public ExternalPrincipal authenticate(AuthenticationToken token) throws AuthenticationException {
		DecodedJWT jwt = getIdTokenCache().getAsJWT(token);

		if(jwt == null) {
			LOGGER.warn("Given authentication token is not a JWT: {}", token);
			return null;
		}

		return finishAuthenticationAndCache(new UserData(jwt));
	}

	public static Builder builder() {
		return new BuilderImpl();
	}

	public interface Builder extends CachingIDTokenAuthHelper.IBuilder<Builder> {

		IDTokenAuthenticator build();

	}

	private static class BuilderImpl implements CachingIDTokenAuthHelper.DelegatingBuilder<Builder>, Builder {
		private final CachingIDTokenAuthHelper.Builder tokenCacheBuilder = CachingIDTokenAuthHelper.builder();

		private final List<String> issuers = new ArrayList<>();

		@Override
		public CachingIDTokenAuthHelper.Builder getCachingIDTokenAuthHelperBuilderDelegate() {
			return tokenCacheBuilder;
		}

		@Override
		public BuilderImpl getThis() {
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
			this.issuers.add(issuer);
			return this;
		}

		@Override
		public Builder addIssuers(Collection<String> issuers) {
			this.issuers.addAll(issuers);
			return this;
		}

		@Override
		public IDTokenAuthenticator build() {
			if(issuers.isEmpty()) {
				throw new IllegalStateException("At least one issuer must be specified.");
			}

			return new IDTokenAuthenticator(issuers.get(0), tokenCacheBuilder.withIssuers(issuers).build());
		}
	}

}
