package com.github.hWorblehat.nexus3.auth.jwt;

import com.github.hWorblehat.nexus3.auth.HeaderTokenExtractor;
import lombok.RequiredArgsConstructor;
import org.sonatype.nexus.capability.CapabilitySupport;
import org.sonatype.nexus.capability.Condition;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.Map;
import java.util.regex.Pattern;

@Named(JWTSearchCapability.NAME)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class JWTSearchCapability extends CapabilitySupport<HeaderTokenExtractor> {

	public static final String NAME = "SearchForJWTHeader";

	static final String P_HEADER = "header";
	static final String P_PATTERN = "pattern";

	static final String JWT_REGEX_PLACEHOLDER = "<jwt>";
	static final Pattern JWT_REGEX = Pattern.compile("[a-zA-Z0-9._\\-]+");

	private final JWTFactory jwtFactory;

	@Override
	public Condition activationCondition() {
		return conditions().capabilities().passivateCapabilityDuringUpdate();
	}

	@Override
	protected HeaderTokenExtractor createConfig(Map<String, String> map) {
		return new HeaderTokenExtractor(
				map.get(P_HEADER),
				Pattern.compile(map.get(P_PATTERN).replace(JWT_REGEX_PLACEHOLDER, JWT_REGEX.pattern()))
		);
	}

	@Override
	protected void onActivate(HeaderTokenExtractor config) {
		jwtFactory.registerHeaderTokenExtractor(config);
	}

	@Override
	protected void onPassivate(HeaderTokenExtractor config) {
		jwtFactory.deregisterHeaderTokenExtractor(config);
	}

	@Nullable
	@Override
	protected String renderDescription() {
		HeaderTokenExtractor config = getConfig();
		return config != null ? config.toString() : null;
	}

}
