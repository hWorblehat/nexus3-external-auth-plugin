package io.github.hWorblehat.nexus3.auth.jwt;

import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.github.hWorblehat.jwt.DynamicJWTVerifier;
import io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal;
import io.github.hWorblehat.nexus3.auth.external.ExternalUserSource;
import io.github.hWorblehat.oidc.IDTokenClaims;
import io.github.hWorblehat.util.Box;
import io.github.hWorblehat.util.DelegateBuilderBase;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.role.RoleIdentifier;
import org.sonatype.nexus.security.user.User;
import org.sonatype.nexus.security.user.UserStatus;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

import static io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal.getUsername;
import static io.github.hWorblehat.nexus3.auth.external.ExternalUserManager.setIssuer;
import static io.github.hWorblehat.nexus3.auth.external.ExternalUserManager.setSubject;

@RequiredArgsConstructor
public class CachingIDTokenAuthHelper<T extends CachingIDTokenAuthHelper.UserData> {
	private static final Logger LOGGER = LoggerFactory.getLogger(CachingIDTokenAuthHelper.class);

	/**
	 * JWT verifier that checks for valid signatures, that the token is in date,
	 * and the the audience and issuer match the configuration of this client.
	 */
	@Getter
	private final JWTVerifier jwtVerifier;
	private final Clock clock;
	private final ConcurrentMap<String, T> users = new ConcurrentHashMap<>();
	private final @Nullable String preferredUsernameClaim;
	private final @Nullable String emailClaim;
	private final @Nullable String firstNameClaim;
	private final @Nullable String lastNameClaim;
	private final @Nullable String rolesClaim;

	@Nullable
	public ExternalPrincipal finishAuthenticationAndCache(String issuer, @Nullable T user) {
		if(user != null) {
			validate(user);
			users.merge(user.getIdToken().getSubject(), user, this::updateVersion);
			return new ExternalPrincipal(
					issuer,
					user.getIdToken().getSubject(),
					getStringClaim(user, preferredUsernameClaim)
			);
		} else {
			return null;
		}
	}

	private T updateVersion(T oldUser, T newUser) {
		newUser.version = oldUser.version;
		if (!fieldsEqual(oldUser, newUser)) {
			newUser.version += 1;
		}
		return newUser;
	}

	public void validate(UserData user) throws AuthenticationException {
		LOGGER.debug("Checking if ID token for {} is valid.", user.getIdToken().getSubject());
		try {
			jwtVerifier.verify(user.getIdToken());
		} catch (Exception e) {
			throw new AuthenticationException("Invalid ID token.", e);
		}
		//TODO Check for ID token claims
		LOGGER.debug("ID token valid.");
	}

	public boolean isInDate(UserData user) {
		return user.getIdToken().getExpiresAt().after(clock.getToday());
	}

	public Set<String> getCachedSubjects() {
		return users.keySet();
	}

	private boolean fieldsEqual(UserData a, UserData b) {
		List<String> rolesA = a.getIdToken().getClaim(rolesClaim).asList(String.class);
		List<String> rolesB = b.getIdToken().getClaim(rolesClaim).asList(String.class);

		return rolesA.size() == rolesB.size() && rolesA.containsAll(rolesB)
				&& Objects.equals(getStringClaim(a, emailClaim), getStringClaim(b, emailClaim))
				&& Objects.equals(getStringClaim(a, firstNameClaim), getStringClaim(b, firstNameClaim))
				&& Objects.equals(getStringClaim(a, lastNameClaim), getStringClaim(b, lastNameClaim));
	}

	@Nullable
	private String getStringClaim(UserData user, String claim) {
		return user.getIdToken().getClaim(claim).asString();
	}

	public String getUserId(UserData user) {
		String preferredUsername = getStringClaim(user, preferredUsernameClaim);
		return getUsername(user.getIdToken().getSubject(), preferredUsername);
	}

	protected boolean matches(T user, BiPredicate<? super String, ? super Collection<String>> test) {
		return test.test(getUserId(user), user.getIdToken().getClaim(rolesClaim).asList(String.class));
	}

	public User toUser(final T user) {
		User asUser = user.asUser;
		if (asUser == null) {
			LOGGER.debug("Parsing ID token to user: {}", user.getIdToken().getClaims());
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("  Subject: {}", user.getIdToken().getSubject());
				LOGGER.debug("  User ID ({}): {}", preferredUsernameClaim, user.getIdToken().getClaim(preferredUsernameClaim));
				LOGGER.debug("  Email ({}): {}", emailClaim, user.getIdToken().getClaim(emailClaim));
				LOGGER.debug("  First name ({}): {}", firstNameClaim, user.getIdToken().getClaim(firstNameClaim));
				LOGGER.debug("  Last name ({}): {}", lastNameClaim, user.getIdToken().getClaim(lastNameClaim));
				LOGGER.debug("  Roles ({}): {}", rolesClaim, user.getIdToken().getClaim(rolesClaim));
			}

			asUser = new User();

			String source = ExternalUserSource.SOURCE;
			List<String> roles = user.getIdToken().getClaim(rolesClaim).asList(String.class);

			asUser.setSource(source);
			asUser.setReadOnly(true);
			asUser.setVersion(user.version);
			asUser.setUserId(getUserId(user));
			asUser.setEmailAddress(getStringClaim(user, emailClaim));
			asUser.setFirstName(getStringClaim(user, firstNameClaim));
			asUser.setLastName(getStringClaim(user, lastNameClaim));
			if (roles != null) {
				roles.stream().map(r -> new RoleIdentifier(source, r)).forEach(asUser::addRole);
			}
			setSubject(asUser, user.getIdToken().getSubject());
			setIssuer(asUser, user.getIdToken().getIssuer());

			LOGGER.debug("Created new user object for {}: {}", user.getIdToken().getSubject(), asUser);

			user.asUser = asUser;
		}

		asUser.setStatus(isInDate(user) ? UserStatus.active : UserStatus.locked);
		LOGGER.debug("User status set to {}", asUser.getStatus());

		return asUser;
	}

	public T updateIfValid(Box<T> existing, T candidate) {
		if (candidate != null && candidate != existing.get()) {
			try {
				validate(candidate);
				updateVersion(existing.get(), candidate);
				existing.set(candidate);
			} catch (AuthenticationException e) {
				LOGGER.debug("New user invalid. Will not replace.", e);
			}
		}
		return existing.get();
	}

	public Stream<Box<T>> streamCache() {
		return users.entrySet().stream().map(Box::ofNonNullMapEntry);
	}

	public Optional<Box<T>> findCachedUser(String subject) {
		return users.containsKey(subject)
				? Optional.of(Box.ofNonNull(() -> users.get(subject), u -> users.put(subject, u)))
				: Optional.empty();
	}

	public T getCachedUser(String subject) {
		return users.get(subject);
	}

	@Nullable
	public DecodedJWT getAsJWT(AuthenticationToken token) {
		return JWTAuthenticationToken.getAsJWT(token, getJwtVerifier());
	}

	public static Builder builder() {
		return new BuilderImpl();
	}

	@RequiredArgsConstructor
	public static class UserData {
		@Getter final @NonNull DecodedJWT idToken;
		@Getter int version = 1;
		@Nullable User asUser;
	}

	public interface IBuilder<B extends IBuilder<B>> extends DynamicJWTVerifier.IBuilder<B> {

		B withPreferredUsernameClaim(String preferredUsernameClaim);

		B withEmailClaim(String emailClaim);

		B withFirstNameClaim(String firstNameClaim);

		B withLastNameClaim(String lastNameClaim);

		B withRolesClaim(String rolesClaim);

	}

	public interface Builder extends IBuilder<Builder> {
		<T extends UserData> CachingIDTokenAuthHelper<T> build();
	}

	private static final class BuilderImpl implements DynamicJWTVerifier.DelegatingBuilder<Builder>, Builder {
		private final DynamicJWTVerifier.Builder verifierBuilder = DynamicJWTVerifier.builder();

		private String preferredUsernameClaim = IDTokenClaims.PREFERRED_USERNAME;
		private String emailClaim = IDTokenClaims.EMAIL;
		private String firstNameClaim;
		private String lastNameClaim;
		private String rolesClaim;

		@Override
		public final Builder getThis() {
			return this;
		}

		@Override
		public DynamicJWTVerifier.Builder getJWTVerifierBuilderDelegate() {
			return verifierBuilder;
		}

		@Override
		public Builder withPreferredUsernameClaim(String preferredUsernameClaim) {
			this.preferredUsernameClaim = preferredUsernameClaim;
			return this;
		}

		@Override
		public Builder withEmailClaim(String emailClaim) {
			this.emailClaim = emailClaim;
			return this;
		}

		@Override
		public Builder withFirstNameClaim(String firstNameClaim) {
			this.firstNameClaim = firstNameClaim;
			return this;
		}

		@Override
		public Builder withLastNameClaim(String lastNameClaim) {
			this.lastNameClaim = lastNameClaim;
			return this;
		}

		@Override
		public Builder withRolesClaim(String rolesClaim) {
			this.rolesClaim = rolesClaim;
			return this;
		}

		public <T extends UserData> CachingIDTokenAuthHelper<T> build() {

			// At present there's no way of passing the clock to the JWT verifier,
			// so we just create a default one based on system time.
			Clock clock = Date::new;

			return new CachingIDTokenAuthHelper<>(
					verifierBuilder.build(), clock,
					preferredUsernameClaim, emailClaim, firstNameClaim, lastNameClaim, rolesClaim
			);
		}

	}

	public interface DelegatingBuilder<B extends IBuilder<B>>
			extends DelegateBuilderBase<B>, DynamicJWTVerifier.DelegatingBuilder<B>, IBuilder<B> {

		IBuilder<?> getCachingIDTokenAuthHelperBuilderDelegate();

		@Override
		default DynamicJWTVerifier.IBuilder<?> getJWTVerifierBuilderDelegate() {
			return getCachingIDTokenAuthHelperBuilderDelegate();
		}

		@Override
		default B withPreferredUsernameClaim(String preferredUsernameClaim) {
			getCachingIDTokenAuthHelperBuilderDelegate().withPreferredUsernameClaim(preferredUsernameClaim);
			return getThis();
		}

		@Override
		default B withEmailClaim(String emailClaim) {
			getCachingIDTokenAuthHelperBuilderDelegate().withEmailClaim(emailClaim);
			return getThis();
		}

		@Override
		default B withFirstNameClaim(String firstNameClaim) {
			getCachingIDTokenAuthHelperBuilderDelegate().withFirstNameClaim(firstNameClaim);
			return getThis();
		}

		@Override
		default B withLastNameClaim(String lastNameClaim) {
			getCachingIDTokenAuthHelperBuilderDelegate().withLastNameClaim(lastNameClaim);
			return getThis();
		}

		@Override
		default B withRolesClaim(String rolesClaim) {
			getCachingIDTokenAuthHelperBuilderDelegate().withRolesClaim(rolesClaim);
			return getThis();
		}
	}

}
