package io.github.hWorblehat.nexus3.auth.jwt.apikey;

import lombok.Value;

@Value
public class JWTAPIKeyCreateResponse {
	String username;
	String password;
}
