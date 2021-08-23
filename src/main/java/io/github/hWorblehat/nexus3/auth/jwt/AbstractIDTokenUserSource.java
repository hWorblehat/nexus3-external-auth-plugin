package io.github.hWorblehat.nexus3.auth.jwt;

import com.auth0.jwt.interfaces.JWTVerifier;
import io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal;
import io.github.hWorblehat.nexus3.auth.external.ExternalUserSource;
import io.github.hWorblehat.util.Box;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.sonatype.nexus.security.user.User;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

import static lombok.AccessLevel.PROTECTED;

@RequiredArgsConstructor(access = PROTECTED)
public abstract class AbstractIDTokenUserSource<T extends CachingIDTokenAuthHelper.UserData> implements ExternalUserSource {

	@Getter(onMethod_ = @Override)
	private final String issuer;
	@Getter(PROTECTED)
	private final CachingIDTokenAuthHelper<T> idTokenCache;

	protected final ExternalPrincipal finishAuthenticationAndCache(T user) {
		return getIdTokenCache().finishAuthenticationAndCache(getIssuer(), user);
	}

	protected User toUser(Box<T> user) {
		return idTokenCache.toUser(user.get());
	}

	@Override
	public final Set<String> getCachedSubjects() {
		return idTokenCache.getCachedSubjects();
	}

	@Override
	public final Optional<User> findCachedUserBySubject(String subject) {
		return idTokenCache.findCachedUser(subject).map(this::toUser);
	}

	@Override
	public final Stream<User> searchCachedUsers(BiPredicate<? super String, ? super Collection<String>> test) {
		return idTokenCache.streamCache().filter(u -> idTokenCache.matches(u.get(), test)).map(this::toUser);
	}

	@Override
	public final Stream<User> streamCachedUsers() {
		return idTokenCache.streamCache().map(this::toUser);
	}

	public JWTVerifier getJWTVerifier() {
		return idTokenCache.getJwtVerifier();
	}



}
