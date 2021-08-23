package io.github.hWorblehat.nexus3.auth.oidc;

import io.github.hWorblehat.nexus3.auth.external.ExternalAuthRealm;
import io.github.hWorblehat.nexus3.auth.external.ExternalUserManager;
import io.github.hWorblehat.nexus3.auth.jwt.JWTFactory;
import lombok.RequiredArgsConstructor;
import org.sonatype.nexus.capability.CapabilitySupport;
import org.sonatype.nexus.capability.Condition;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.Map;

@Named(OIDCCapability.NAME)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class OIDCCapability extends CapabilitySupport<OIDCAuthenticator> {

	public static final String NAME = "OpenIDConnect";

	private final ExternalAuthRealm authRealm;
	private final JWTFactory jwtFactory;
	private final ExternalUserManager userManager;

	@Override
	public Condition activationCondition() {
		return conditions().capabilities().passivateCapabilityDuringUpdate();
	}

	@Override
	protected OIDCAuthenticator createConfig(Map<String, String> map) {
		return ((OIDCCapabilityDescriptor) context().descriptor()).createClient(map);
	}

	@Override
	protected void onActivate(OIDCAuthenticator config) {
		authRealm.registerAuthenticator(config);
		userManager.registerUserSource(config);
		jwtFactory.registerJWTVerifier(config.getIssuer(), config.getJWTVerifier());
	}

	@Override
	protected void onPassivate(OIDCAuthenticator config) throws Exception {
		jwtFactory.deregisterJWTVerifier(config.getIssuer());
		userManager.deregisterUserSource(config);
		authRealm.deregisterAuthenticator(config);
		config.close();
	}

	@Nullable
	@Override
	protected String renderDescription() {
		OIDCAuthenticator client = getConfig();
		return client == null ? null : "Issuer: " + client.getIssuer();
	}
}
