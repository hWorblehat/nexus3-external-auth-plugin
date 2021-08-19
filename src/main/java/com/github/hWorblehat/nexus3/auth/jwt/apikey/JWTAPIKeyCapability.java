package com.github.hWorblehat.nexus3.auth.jwt.apikey;

import com.github.hWorblehat.nexus3.auth.jwt.JWTFactory;
import lombok.RequiredArgsConstructor;
import org.sonatype.nexus.capability.CapabilitySupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.capability.Condition;
import org.sonatype.nexus.security.realm.RealmManager;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Map;

import static org.sonatype.nexus.capability.CapabilityType.capabilityType;

@Named(JWTAPIKeyCapability.NAME)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class JWTAPIKeyCapability extends CapabilitySupport<JWTAPIKeyConfig> {

	public static final String NAME = "JWS_API_Key";
	public static final CapabilityType TYPE = capabilityType(NAME);

	private final JWTAPIKeyResource api;
	private final JWTFactory jwtFactory;
	private final JWTAPIKeyAuthRealm authRealm;
	private final RealmManager realmManager;

	@Override
	public Condition activationCondition() {
		return conditions().capabilities().passivateCapabilityDuringUpdate();
	}

	@Override
	protected JWTAPIKeyConfig createConfig(Map<String, String> map) {
		return ((JWTAPIKeyCapabilityDescriptor) context().descriptor()).createAPIKeyConfig(map);
	}

	@Override
	protected void onActivate(JWTAPIKeyConfig config) {
		api.configure(config);
		authRealm.configure(config);
		jwtFactory.registerJWTVerifier(config.getIssuer(), config.getVerifier());
		realmManager.enableRealm(JWTAPIKeyAuthRealm.NAME);
	}

	@Override
	protected void onPassivate(JWTAPIKeyConfig config) {
		realmManager.disableRealm(JWTAPIKeyAuthRealm.NAME);
		jwtFactory.deregisterJWTVerifier(config.getIssuer());
	}

}
