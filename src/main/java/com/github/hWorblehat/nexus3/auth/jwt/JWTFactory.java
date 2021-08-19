package com.github.hWorblehat.nexus3.auth.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.github.hWorblehat.nexus3.auth.HeaderTokenExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.authc.AuthenticationTokenFactory;

import javax.annotation.Nullable;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

import static java.lang.Math.min;
import static java.util.stream.Collectors.toList;
import static org.apache.shiro.web.util.WebUtils.toHttp;

@Named
@Singleton
public class JWTFactory implements AuthenticationTokenFactory {
	private static final Logger LOGGER = LoggerFactory.getLogger(JWTFactory.class);

	private final Set<HeaderTokenExtractor> extractors = new HashSet<>();
	private final Map<String, JWTVerifier> verifiers = new HashMap<>();

	@Nullable
	@Override
	public JWTAuthenticationToken createToken(ServletRequest servletRequest, ServletResponse servletResponse) {
		LOGGER.debug("Looking for JWTs on request from {}", servletRequest.getRemoteAddr());
		HttpServletRequest request = toHttp(servletRequest);
		List<DecodedJWT> jwts = extractors
				.stream()
				.map(ex -> ex.extract(request))
				.filter(Objects::nonNull)
				.distinct()
				.map(this::toJWT)
				.filter(Objects::nonNull)
				.collect(toList());

		if(jwts.isEmpty()) {
			return null;
		}

		if(jwts.size() > 1) {
			LOGGER.warn("Multiple JWTs found on request from {}. Only one will be used as an authentication token.",
					request.getRemoteAddr());
		}

		JWTAuthenticationToken token = new JWTAuthenticationToken(jwts.get(0));
		LOGGER.debug("Found JWT on request from {}: {}", request.getRemoteAddr(), token);
		return token;
	}

	@Nullable
	private DecodedJWT toJWT(String candidate) {
		final DecodedJWT jwt;
		try {
			jwt = JWT.decode(candidate);
		} catch (Exception e) {
			LOGGER.debug("Attempt to decode JWT candidate {}... failed.",
					candidate.subSequence(0, min(20, candidate.length())), e);
			return null;
		}
		LOGGER.debug("JWT found. Attempting to verify [iss={}; sub={}]", jwt.getIssuer(), jwt.getSubject());
		for(JWTVerifier verifier: verifiers.values()) {
			try {
				return verifier.verify(jwt);
			} catch (Exception e) {
				LOGGER.trace("Attempt to verify JWT candidate failed.", e);
			}
		}
		LOGGER.debug("No registered JWT verifier successfully verified JWT.");
		return null;
	}

	public void registerHeaderTokenExtractor(HeaderTokenExtractor extractor) throws IllegalStateException {
		if(!extractors.add(extractor)) {
			throw new IllegalStateException("Header token extractor " + extractor + " already exists.");
		}
		LOGGER.info("Added JWT token candidate extractor: {}", extractor);
	}

	public void deregisterHeaderTokenExtractor(HeaderTokenExtractor extractor) {
		extractors.remove(extractor);
		LOGGER.info("Removed JWT token candidate extractor: {}", extractor);
	}

	public void registerJWTVerifier(String name, JWTVerifier verifier) throws IllegalStateException {
		JWTVerifier existing = verifiers.putIfAbsent(name, verifier);
		if(existing != null) {
			throw new IllegalStateException("JWT verifier with name " + name + " already exists.");
		}
		LOGGER.info("Added JWT verifier: {}", name);
	}

	public void deregisterJWTVerifier(String name) {
		verifiers.remove(name);
		LOGGER.info("Remove JWT verifier: {}", name);
	}

}
