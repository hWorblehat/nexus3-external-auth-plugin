package io.github.hWorblehat.nexus3.auth.external;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.role.RoleIdentifier;
import org.sonatype.nexus.security.user.*;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.*;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

@Singleton
@Named(ExternalUserSource.SOURCE)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class ExternalUserManager extends AbstractReadOnlyUserManager implements UserManager {
	private static final Logger LOGGER = LoggerFactory.getLogger(ExternalUserManager.class);

	private static final String ISSUER_ROLE_SOURCE = "__hWorblehat_ext_iss";
	private static final String SUBJECT_ROLE_SOURCE = "__hWorblehat_ext_sub";
	public static final Set<String> NON_AUTH_ROLES = unmodifiableSet(new HashSet<>(Arrays.asList(
			ISSUER_ROLE_SOURCE, SUBJECT_ROLE_SOURCE
	)));

	private final Map<String, ExternalUserSource> sources = new HashMap<>();

	@Override
	public String getSource() {
		return ExternalUserSource.SOURCE;
	}

	@Override
	public String getAuthenticationRealmName() {
		return ExternalAuthRealm.NAME;
	}

	@Override
	public Set<User> listUsers() {
		Set<User> users = sources.values().stream()
				.flatMap(ExternalUserSource::streamCachedUsers)
				.collect(toSet());
		LOGGER.debug("Listing {} external users.", users.size());
		return users;
	}

	@Override
	public Set<String> listUserIds() {
		Set<String> ids = sources.values().stream()
				.flatMap(s -> s.getCachedSubjects().stream())
				.collect(toSet());
		LOGGER.debug("Listing {} external user IDs.", ids.size());
		return ids;
	}

	@Override
	public Set<User> searchUsers(UserSearchCriteria criteria) {
		LOGGER.debug("Searching for external uses.");
		String source = getSource();
		if(criteria.getSource() != null && !criteria.getSource().equals(source)) {
			LOGGER.debug("User search criteria does not match '{}' source.", source);
			return emptySet();
		}

		BiPredicate<String, Collection<String>> test = (id, roles) -> matchesCriteria(id, source, roles, criteria);
		Set<User> users = sources.values().stream()
				.flatMap(s -> s.searchCachedUsers(test))
				.collect(toSet());
		LOGGER.debug("Found {} users.", users.size());
		return users;
	}

	@Override
	public User getUser(String id) throws UserNotFoundException {
		LOGGER.debug("Looking up external user: {}", id);
		Optional<User> user = findByUserID(id);
		if(!user.isPresent()) {
			user = findBySubject(id);
		}
		return user.orElseThrow(() -> new UserNotFoundException(id));
	}

	public Optional<User> findBySubject(String issuer, String subject) {
		return Optional.ofNullable(sources.get(issuer))
				.flatMap(s -> s.findCachedUserBySubject(subject));
	}

	public Optional<User> findBySubject(String subject) {
		return sources.values().stream()
				.flatMap(s -> s.findCachedUserBySubject(subject).map(Stream::of).orElseGet(Stream::empty))
				.findFirst();
	}

	private BiPredicate<String, Object> matchUserID(String userId) {
		return (id, roles) -> userId.equalsIgnoreCase(id);
	}

	public Optional<User> findByUserID(String issuer, String userId) {
		return Optional.ofNullable(sources.get(issuer))
				.flatMap(s -> s.searchCachedUsers(matchUserID(userId)).findAny());
	}

	public Optional<User> findByUserID(String userId) {
		BiPredicate<String, Object> test = matchUserID(userId);
		return sources.values().stream()
				.flatMap(s -> s.searchCachedUsers(test))
				.findAny();
	}

	public void registerUserSource(ExternalUserSource source) {
		ExternalUserSource existing = sources.putIfAbsent(source.getIssuer(), source);
		if(existing != null) {
			throw new IllegalStateException("User source for issuer '" + source.getIssuer() + "' already exists.");
		}
		LOGGER.info("Registered external user source: {}", source.getIssuer());
	}

	public void deregisterUserSource(ExternalUserSource source) {
		ExternalUserSource removed = sources.remove(source.getIssuer());
		if(removed == null) {
			LOGGER.warn("External user source with ID '{}' did not exist.", source.getIssuer());
		}
		LOGGER.info("Deregistered external user source: {}", source.getIssuer());
	}

	@Nullable
	private static String getRoleProperty(User user, String source) {
		return user.getRoles().stream()
				.filter(r -> source.equals(r.getSource()))
				.map(RoleIdentifier::getRoleId)
				.findFirst()
				.orElse(null);
	}

	@Nullable
	public static String getSubject(User user) {
		return getRoleProperty(user, SUBJECT_ROLE_SOURCE);
	}

	@Nullable
	public static String getIssuer(User user) {
		return getRoleProperty(user, ISSUER_ROLE_SOURCE);
	}

	private static void setRoleProperty(User user, String key, String value) {
		RoleIdentifier roleId = user.getRoles().stream()
				.filter(r -> key.equals(r.getSource()))
				.findFirst()
				.orElse(null);

		if(roleId != null) {
			user.removeRole(roleId);
			roleId.setRoleId(value);
		} else {
			roleId = new RoleIdentifier(key, value);
		}
		user.addRole(roleId);
	}

	public static void setSubject(User user, String subject) {
		setRoleProperty(user, SUBJECT_ROLE_SOURCE, subject);
	}

	public static void setIssuer(User user, String issuer) {
		setRoleProperty(user, ISSUER_ROLE_SOURCE, issuer);
	}

}
