package com.github.hWorblehat.nexus3.auth.external;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.role.RoleIdentifier;
import org.sonatype.nexus.security.user.User;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.github.hWorblehat.nexus3.auth.external.ExternalUserManager.NON_AUTH_ROLES;
import static java.util.stream.Collectors.toSet;

@Singleton
@Named(ExternalAuthRealm.NAME)
@Description("External Realm (JWT and OpenID connect)")
public class ExternalAuthRealm extends AuthorizingRealm {
	private static final Logger LOGGER = LoggerFactory.getLogger(ExternalAuthRealm.class);

	public static final String NAME = "External";

	private final Map<String, ExternalAuthenticator> authenticators = new HashMap<>();
	private final ExternalUserManager userManager;

	@Inject
	public ExternalAuthRealm(ExternalUserManager userManager) {
		super(new AllowAllCredentialsMatcher());
		this.userManager = userManager;
		setCachingEnabled(false);
		setAuthenticationCachingEnabled(false);
		setAuthorizationCachingEnabled(false);
	}


	@Override
	public boolean supports(AuthenticationToken token) {
		return authenticators.containsKey(token.getPrincipal().toString());
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		LOGGER.debug("Checking for authenticator for issuer: {}", token.getPrincipal());
		ExternalAuthenticator authenticator = authenticators.get(token.getPrincipal().toString());
		if(authenticator != null) {
			LOGGER.debug("Authenticator found. Attempting to authenticate.");
			Object principal = authenticator.authenticate(token);
			if(principal != null) {
				LOGGER.debug("Successfully authenticated user: {}", principal);
				return new SimpleAuthenticationInfo(principal, token.getCredentials(), NAME);
			}
		}
		return null;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		LOGGER.debug("Looking up external user: {}", principalCollection);
		ExternalPrincipal ext = ExternalPrincipal.asExternal(principalCollection);
		if(ext != null) {
			LOGGER.debug("Looking up by subject: {}", ext.getSubject());
			User user = userManager
					.findBySubject(ext.getIssuer(), ext.getSubject())
					.filter(u -> u.getStatus().isActive())
					.orElse(null);
			if(user != null) {
				Set<String> roles = user.getRoles().stream()
						.filter(r -> !NON_AUTH_ROLES.contains(r.getSource()))
						.map(RoleIdentifier::getRoleId)
						.collect(toSet());
				LOGGER.debug("Found roles: {}", roles);
				return new SimpleAuthorizationInfo(roles);
			}
		}
		LOGGER.debug("External user not found: {}", principalCollection);
		return null;
	}

	public void registerAuthenticator(ExternalAuthenticator authenticator) {
		ExternalAuthenticator existing = authenticators.putIfAbsent(authenticator.getIssuer(), authenticator);
		if(existing != null) {
			throw new IllegalStateException("Authenticator already exists for issuer: " + authenticator.getIssuer());
		}
		LOGGER.info("Registered external authenticator for issuer: {}", authenticator.getIssuer());
	}

	public void deregisterAuthenticator(ExternalAuthenticator authenticator) {
		ExternalAuthenticator removed = authenticators.remove(authenticator.getIssuer());
		if(removed == null) {
			LOGGER.warn("External authenticator for issuer '{}' did not exist.", authenticator.getIssuer());
		}
		LOGGER.info("Deregistered external authenticator for {}", authenticator.getIssuer());
	}

	public void deregisterAuthenticator(String issuer) {
		authenticators.remove(issuer);
		LOGGER.info("Deregistered external authenticator for {}", issuer);
	}

}
