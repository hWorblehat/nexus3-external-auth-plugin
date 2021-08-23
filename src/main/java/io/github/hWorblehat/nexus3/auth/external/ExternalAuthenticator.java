package io.github.hWorblehat.nexus3.auth.external;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

import javax.annotation.Nullable;

public interface ExternalAuthenticator {

	String getIssuer();

	@Nullable
	Object authenticate(AuthenticationToken token) throws AuthenticationException;

}
