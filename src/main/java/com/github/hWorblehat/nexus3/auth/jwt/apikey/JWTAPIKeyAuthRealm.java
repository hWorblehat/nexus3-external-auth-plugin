package com.github.hWorblehat.nexus3.auth.jwt.apikey;

import com.auth0.jwt.interfaces.JWTVerifier;
import com.github.hWorblehat.nexus3.auth.jwt.JWTAuthenticationToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

@Singleton
@Named
@Description("JWT API key realm")
public class JWTAPIKeyAuthRealm extends AuthenticatingRealm {

	public static final String NAME = JWTAPIKeyAuthRealm.class.getName();

	private final JWTAPIKeys keyIdStore;
	private String issuer = null;
	private JWTVerifier verifier = null;

	@Inject
	public JWTAPIKeyAuthRealm(JWTAPIKeys keyIdStore) {
		super(new AllowAllCredentialsMatcher());
		this.keyIdStore = keyIdStore;
		setAuthenticationCachingEnabled(false);
	}

	public void configure(JWTAPIKeyConfig config) {
		this.issuer = config.getIssuer();
		this.verifier = config.getVerifier();
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		checkConfigured();
		return issuer.equals(token.getPrincipal()) && token instanceof JWTAuthenticationToken;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		checkConfigured();
		PrincipalCollection principals = keyIdStore.toPrincipalCollection(
				JWTAuthenticationToken.getAsJWT(token, verifier)
		);
		return principals == null ? null : new SimpleAuthenticationInfo(principals, token.getCredentials());
	}

	private void checkConfigured() {
		if(issuer == null || verifier == null) {
			throw new IllegalStateException(getClass().getSimpleName() + " enabled but not configured.");
		}
	}

}
