package io.github.hWorblehat.nexus3.auth.jwt.apikey;

import lombok.RequiredArgsConstructor;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.PrincipalCollection;
import org.sonatype.nexus.rest.Resource;
import org.sonatype.nexus.rest.WebApplicationMessageException;
import org.sonatype.nexus.security.SecurityHelper;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.ws.rs.*;
import java.util.List;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.Status.NOT_FOUND;
import static javax.ws.rs.core.Response.Status.NOT_IMPLEMENTED;

@Singleton
@Named
@RequiredArgsConstructor(onConstructor_ = @Inject)
@Produces({APPLICATION_JSON})
@Path("jwtapikey")
public class JWTAPIKeyResource implements Resource {

	private final SecurityHelper securityHelper;
	private final JWTAPIKeys apiKeys;

	private JWTAPIKeyConfig config = null;

	public void configure(JWTAPIKeyConfig config) {
		this.config = config;
	}

	@GET
	@RequiresUser
	public List<String> listKeys() {
		checkConfigured();
		return apiKeys.list(getCurrentUser());
	}

	@PUT
	@Path("{key}")
	@RequiresUser
	public String createKey(@PathParam("key") String key) {
		checkConfigured();
		return apiKeys.create(getCurrentUser(), key, config);
	}

	@DELETE
	@Path("{key}")
	@RequiresUser
	@RequiresAuthentication
	public void deleteKey(@PathParam("key") String key) {
		checkConfigured();
		if(!apiKeys.delete(getCurrentUser(), key)) {
			throw new WebApplicationMessageException(NOT_FOUND, "No JWT API key '" + key + "' found.");
		}
	}

	private PrincipalCollection getCurrentUser() {
		return securityHelper.subject().getPrincipals();
	}

	private void checkConfigured() {
		if(config == null) {
			throw new WebApplicationMessageException(NOT_IMPLEMENTED,
					"The JWT API key capability has not been configured.");
		}
	}

}
