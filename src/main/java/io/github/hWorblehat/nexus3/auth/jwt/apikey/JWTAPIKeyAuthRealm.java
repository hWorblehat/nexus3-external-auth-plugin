package io.github.hWorblehat.nexus3.auth.jwt.apikey;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.github.hWorblehat.nexus3.auth.jwt.JWTAuthenticationToken;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

@Singleton
@Named
@Description("JWT API key realm")
public class JWTAPIKeyAuthRealm extends AuthenticatingRealm {
	private static final Logger LOGGER = LoggerFactory.getLogger(JWTAPIKeyAuthRealm.class);

	public static final String NAME = JWTAPIKeyAuthRealm.class.getName();
	public static final String DUMMY_USERNAME = "jwtapikey";

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
		return (issuer.equals(token.getPrincipal()) && token instanceof JWTAuthenticationToken)
				|| (DUMMY_USERNAME.equals(token.getPrincipal()) && token instanceof UsernamePasswordToken);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		checkConfigured();
		PrincipalCollection principals = keyIdStore.toPrincipalCollection(getJwt(token));
		return principals == null ? null : new SimpleAuthenticationInfo(principals, token.getCredentials());
	}

	private void checkConfigured() {
		if(issuer == null || verifier == null) {
			throw new IllegalStateException(getClass().getSimpleName() + " enabled but not configured.");
		}
	}

	private DecodedJWT getJwt(AuthenticationToken token) {
		if(token instanceof UsernamePasswordToken) {
			LOGGER.debug("Checking if password is valid JWT.");
			try {
				return verifier.verify(token.getCredentials().toString());
			} catch (JWTVerificationException e) {
				LOGGER.debug("JWT verification failed.", e);
				return null;
			}
		} else {
			return JWTAuthenticationToken.getAsJWT(token, verifier);
		}
	}

}
