package io.github.hWorblehat.nexus3.auth.external;

import org.sonatype.nexus.security.user.User;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

public interface ExternalUserSource {

	String SOURCE = "External";

	String getIssuer();

	Set<String> getCachedSubjects();

	Optional<User> findCachedUserBySubject(String subject);

	Stream<User> searchCachedUsers(BiPredicate<? super String, ? super Collection<String>> test);

	default Stream<User> streamCachedUsers() {
		return searchCachedUsers((id, roles) -> true);
	}

}
