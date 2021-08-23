package io.github.hWorblehat.nexus3.auth.external;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.subject.PrincipalCollection;

import javax.annotation.Nullable;
import java.io.Serializable;

import static java.util.Objects.hash;

@RequiredArgsConstructor
public final class ExternalPrincipal implements Serializable {
	private static final long serialVersionUID = 1L;

	@Getter
	private final String issuer;
	@Getter
	private final String subject;
	private final @Nullable String preferredUsername;

	public String getUsername() {
		return getUsername(subject, preferredUsername);
	}

	@Override
	public int hashCode() {
		return hash(issuer, subject);
	}

	@Override
	public boolean equals(Object o) {
		if(this == o) return true;
		if(o instanceof ExternalPrincipal) {
			ExternalPrincipal other = (ExternalPrincipal) o;
			return issuer.equals(other.issuer) && subject.equals(other.subject);
		}
		return false;
	}

	@Override
	public String toString() {
		return getUsername();
	}

	public static String getUsername(String subject, @Nullable String preferredUsername) {
		return preferredUsername != null ? preferredUsername : subject;
	}

	@Nullable
	public static ExternalPrincipal asExternal(PrincipalCollection principals) {
		if(principals.getRealmNames().contains(ExternalAuthRealm.NAME)
				&& principals.getPrimaryPrincipal() instanceof ExternalPrincipal
		) {
			return (ExternalPrincipal) principals.getPrimaryPrincipal();
		}
		return null;
	}

}
