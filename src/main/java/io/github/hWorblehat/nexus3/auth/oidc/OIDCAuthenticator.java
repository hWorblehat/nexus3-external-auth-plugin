package io.github.hWorblehat.nexus3.auth.oidc;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hWorblehat.jwt.PublicKeyProvider;
import io.github.hWorblehat.nexus3.auth.external.ExternalAuthenticator;
import io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal;
import io.github.hWorblehat.nexus3.auth.external.ExternalUserSource;
import io.github.hWorblehat.nexus3.auth.jwt.AbstractIDTokenUserSource;
import io.github.hWorblehat.nexus3.auth.jwt.CachingIDTokenAuthHelper;
import io.github.hWorblehat.oauth2.OAuth2Client;
import io.github.hWorblehat.oidc.OpenIDConfiguration;
import io.github.hWorblehat.util.Box;
import lombok.NonNull;
import org.apache.commons.io.function.IOSupplier;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.user.User;

import javax.annotation.Nullable;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static io.github.hWorblehat.oauth2.OAuth2Client.onBehalfOf;
import static io.github.hWorblehat.oauth2.OAuth2Client.refresh;
import static java.util.Collections.unmodifiableSet;
import static java.util.Objects.requireNonNull;

public class OIDCAuthenticator extends AbstractIDTokenUserSource<OIDCAuthenticator.UserData>
		implements ExternalUserSource, Closeable, ExternalAuthenticator {
	private static final Logger LOGGER  = LoggerFactory.getLogger(OIDCAuthenticator.class);

	private static final Set<String> DEFAULT_REQUIRED_SCOPES = unmodifiableSet(new HashSet<>(Arrays.asList(
			"openid", "profile", "email", "offline_access"
	)));

	private final OAuth2Client oAuth2Client;
	private final Set<String> requiredScopes;

	private OIDCAuthenticator(
			String issuer,
			CachingIDTokenAuthHelper<UserData> idTokenCache,
			OAuth2Client oAuth2Client,
			Set<String> requiredScopes
	) {
		super(issuer, idTokenCache);
		this.oAuth2Client = oAuth2Client;
		this.requiredScopes = requiredScopes;
	}

	@Override
	public ExternalPrincipal authenticate(AuthenticationToken token) {

		// Option 1 - Attempt authorization with auth code
		UserData user = authenticateAsAuthCode(token);

		DecodedJWT jwt = user == null ? getIdTokenCache().getAsJWT(token) : null;

		// Option 2 - If we have a JWT, lookup cached user and attempt refresh
		if(user == null && jwt != null) {
			LOGGER.debug("Attempting to find and refresh existing user based on JWT subject: {}", jwt.getSubject());
			user = ensureInDate(getIdTokenCache().getCachedUser(jwt.getSubject()));
		}

		// Option 3 - Try using the token as an OAuth2 access token with the on_behalf_of flow
		if(user == null) {
			LOGGER.debug("Attempting to authenticate user by using authentication token as an access token with the on-behalf-of flow.");
			user = requestToken(onBehalfOf(token.getCredentials().toString()));
		}

		// Option 4 - If we have a JWT, see if we can use it directly as an ID token
		if(user == null && jwt != null) {
			LOGGER.debug("Attempting to use JWT authentication token as an ID token directly: {}", token);
			user = new UserData(jwt);
		}

		return finishAuthenticationAndCache(user);
	}

	@Nullable
	private UserData authenticateAsAuthCode(AuthenticationToken token) {
		//TODO
		return null;
	}

	private UserData ensureInDate(UserData user) {
		if(user != null && !getIdTokenCache().isInDate(user)) {
			LOGGER.info("ID token for {} is out of date", user.getIdToken().getSubject());
			if(user.refreshToken != null) {
				LOGGER.info("Refreshing token");
				user = requestToken(refresh(user.refreshToken));
			} else {
				LOGGER.info("No refresh token available");
				user = null;
			}
		}
		return user;
	}

	@Nullable
	private UserData requestToken(Map<String, String> parameters) {
		final JsonNode tokenResponse;
		try {
			tokenResponse = oAuth2Client.token(parameters, requiredScopes);
		} catch (IOException e) {
			LOGGER.debug("Token request to OAuth issuer failed.", e);
			return null;
		}

		final DecodedJWT idToken;
		try {
			idToken = JWT.decode(tokenResponse.get("id_token").asText());
		} catch (Exception e) {
			LOGGER.warn("OAuth2 token endpoint did not return ID token.", e);
			return null;
		}

		UserData user = new UserData(idToken);

		try {
			user.refreshToken = tokenResponse.get("refresh_token").asText();
		} catch (Exception e) {
			LOGGER.warn("Issuer did not supply refresh token in response.", e);
		}

		return user;
	}

	@Override
	protected User toUser(Box<UserData> user) {
		UserData refreshed = ensureInDate(user.get());
		return getIdTokenCache().toUser(getIdTokenCache().updateIfValid(user, refreshed));
	}

	@Override
	public void close() throws IOException {
		oAuth2Client.close();
	}

	public static Builder builder() {
		return new BuilderImpl();
	}

	protected static class UserData extends CachingIDTokenAuthHelper.UserData {
		@Nullable String refreshToken;

		protected UserData(@NonNull DecodedJWT idToken) {
			super(idToken);
		}
	}

	public interface Builder extends OAuth2Client.IBuilder<Builder>, CachingIDTokenAuthHelper.IBuilder<Builder>  {

		Builder withJwksURI(IOSupplier<URI> jwksURI);

		Builder withJwksURI(URI jwksURI);

		Builder withJwksURI(String jwksURI);

		Builder withIssuerURI(URI issuer);

		default Builder withIssuerURI(String issuer) {
			return withIssuerURI(URI.create(issuer));
		}

		Builder withConfiguration(OpenIDConfiguration config);

		Builder withRequiredScopes(Set<String> requiredScopes);

		OIDCAuthenticator build();
	}

	private static final class BuilderImpl implements
			OAuth2Client.DelegateBuilder<Builder>,
			CachingIDTokenAuthHelper.DelegatingBuilder<Builder>,
			Builder {
		private final OAuth2Client.Builder clientBuilder = OAuth2Client.builder();
		private final CachingIDTokenAuthHelper.Builder tokenCacheBuilder = CachingIDTokenAuthHelper.builder();

		private URI issuerURI;
		private String clientId;
		private HttpClient httpClient;
		private ObjectMapper objectMapper;
		private IOSupplier<URI> tokenEndpoint;
		private IOSupplier<URI> jwksURI;
		private Set<String> requiredScopes = DEFAULT_REQUIRED_SCOPES;

		@Override
		public final Builder getThis() {
			return this;
		}

		@Override
		public OAuth2Client.Builder getOAuth2ClientBuilderDelegate() {
			return clientBuilder;
		}

		@Override
		public CachingIDTokenAuthHelper.Builder getCachingIDTokenAuthHelperBuilderDelegate() {
			return tokenCacheBuilder;
		}

		@Override
		public Builder withBorrowedHttpClient(HttpClient httpClient) {
			clientBuilder.withBorrowedHttpClient(httpClient);
			this.httpClient = httpClient;
			return this;
		}

		@Override
		public Builder withOwnedHttpClient(CloseableHttpClient httpClient) {
			clientBuilder.withOwnedHttpClient(httpClient);
			this.httpClient = httpClient;
			return this;
		}

		@Override
		public Builder withObjectMapper(ObjectMapper objectMapper) {
			clientBuilder.withObjectMapper(objectMapper);
			this.objectMapper = objectMapper;
			return this;
		}

		@Override
		public Builder withTokenEndpoint(IOSupplier<URI> tokenEndpoint) {
			this.tokenEndpoint = tokenEndpoint;
			return this;
		}

		@Override
		public Builder withClientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		@Override
		public Builder withClientSecret(String clientSecret) {
			clientBuilder.withClientSecret(clientSecret);
			tokenCacheBuilder.withHMACSecret(clientSecret.getBytes(StandardCharsets.UTF_8));
			return this;
		}

		@Override
		public Builder withJwksURI(IOSupplier<URI> jwksURI) {
			this.jwksURI = jwksURI;
			return this;
		}

		@Override
		public Builder withJwksURI(URI jwksURI) {
			requireNonNull(jwksURI);
			return withJwksURI(() -> jwksURI);
		}

		@Override
		public Builder withJwksURI(String jwksURI) {
			return withJwksURI(URI.create(jwksURI));
		}

		@Override
		public Builder withIssuerURI(URI issuer) {
			this.issuerURI = issuer;
			return this;
		}

		@Override
		public Builder withConfiguration(OpenIDConfiguration config) {
			withIssuerURI(config.getIssuer());
			withTokenEndpoint(config.getTokenEndpoint());
			withJwksURI(config.getTokenEndpoint());
			return this;
		}

		@Override
		public Builder withRequiredScopes(Set<String> requiredScopes) {
			this.requiredScopes = requiredScopes;
			return this;
		}

		@Override
		public OIDCAuthenticator build() {

			if(objectMapper == null) {
				withObjectMapper(new ObjectMapper());
			}

			URI issuerURI = requireNonNull(this.issuerURI);
			String clientId = requireNonNull(this.clientId);
			HttpClient httpClient = requireNonNull(this.httpClient);
			String issuer = issuerURI.toString();

			IOSupplier<URI> tokenEndpoint = this.tokenEndpoint;
			IOSupplier<URI> jwksURI = this.jwksURI;
			if(tokenEndpoint == null || jwksURI == null) {
				IOSupplier<OpenIDConfiguration> config = OpenIDConfiguration
						.fromIssuerURI(httpClient, objectMapper, issuerURI)
						.withCaching();

				if(tokenEndpoint == null) {
					tokenEndpoint = () -> config.get().getTokenEndpoint();
				}

				if(jwksURI == null) {
					jwksURI = () -> config.get().getJwksUri();
				}
			}

			return new OIDCAuthenticator(
					issuer,
					tokenCacheBuilder
							.addIssuer(issuer)
							.addAudience(clientId)
							.withKeyProvider(PublicKeyProvider.fromJwksUri(objectMapper, httpClient, jwksURI))
							.build(),
					clientBuilder
							.withClientId(clientId)
							.withTokenEndpoint(tokenEndpoint)
							.build(),
					requireNonNull(requiredScopes)
			);
		}

	}

}
