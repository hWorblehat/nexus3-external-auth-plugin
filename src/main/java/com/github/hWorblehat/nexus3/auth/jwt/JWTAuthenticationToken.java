package com.github.hWorblehat.nexus3.auth.jwt;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.Value;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

@Value
public class JWTAuthenticationToken implements AuthenticationToken {
	private static final Logger LOGGER = LoggerFactory.getLogger(JWTAuthenticationToken.class);

	DecodedJWT jwt;

	@Override
	public String getPrincipal() {
		return jwt.getIssuer();
	}

	@Override
	public String getCredentials() {
		return jwt.getToken();
	}

	@Override
	public String toString() {
		return "JWT(iss=" + jwt.getIssuer() + "; sub=" + jwt.getSubject() + ")";
	}

	@Nullable
	public static DecodedJWT getAsJWT(AuthenticationToken token, JWTVerifier verifier) {
		LOGGER.debug("Checking if authentication token is JWT: {}", token);
		if(token instanceof JWTAuthenticationToken) {
			DecodedJWT jwt = ((JWTAuthenticationToken) token).getJwt();
			try {
				verifier.verify(jwt);
				LOGGER.debug("It is!");
				return jwt;
			} catch (Exception e) {
				LOGGER.debug("{} not valid.", token, e);
			}
		}
		return null;
	}

}
