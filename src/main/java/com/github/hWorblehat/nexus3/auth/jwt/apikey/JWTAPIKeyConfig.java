package com.github.hWorblehat.nexus3.auth.jwt.apikey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class JWTAPIKeyConfig {
	private final String issuer;
	private final String audience;
	private final Algorithm algorithm;
	private final JWTVerifier verifier;

	public JWTAPIKeyConfig(String issuer, String audience, Algorithm algorithm) {
		this(issuer, audience, algorithm, JWT.require(algorithm)
				.withIssuer(issuer)
				.withAudience(audience)
				.build()
		);
	}

	public JWTAPIKeyConfig(String issuer, Algorithm algorithm) {
		this(issuer, issuer, algorithm);
	}

}
