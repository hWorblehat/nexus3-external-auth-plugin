package io.github.hWorblehat.nexus3.auth.jwt.apikey;

import org.sonatype.goodies.i18n.I18N;
import org.sonatype.goodies.i18n.MessageBundle;
import org.sonatype.nexus.capability.CapabilityDescriptorSupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.PasswordFormField;
import org.sonatype.nexus.formfields.StringTextFormField;

import javax.inject.Named;
import javax.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.auth0.jwt.algorithms.Algorithm.*;

@Singleton
@Named(JWTAPIKeyCapabilityDescriptor.NAME)
public class JWTAPIKeyCapabilityDescriptor extends CapabilityDescriptorSupport<Void> {

	public static final String NAME = "JWT_API_Key";

	private interface Messages extends MessageBundle {

		@DefaultMessage("JWT API keys")
		String name();

		@DefaultMessage("Allow users to generate JWS API keys for non-interactive logins")
		String about();

		@DefaultMessage("Issuer")
		String issuerLabel();

		@DefaultMessage("The 'iss' JWT claim to use, to help identify where JWTs come from. " +
				"Changing this will cause all previously generated keys to be invalidated.")
		String issuerHelp();

		@DefaultMessage("Signing secret")
		String hmacSecretLabel();

		@DefaultMessage("A secret key used to sign and verify JWTs. Must be at least %d characters long. " +
				"Changing this will cause all previously generated keys to be invalidated.")
		String hmacSecretHelp(int minSecretLength);

	}

	private static final String P_ISSUER = "issuer";
	private static final String P_HMAC_SIGNING_SECRET = "hmacSigningSecret";

	private static final int MIN_SECRET_LENGTH = 256/8;

	private final Messages messages = I18N.create(Messages.class);

	@SuppressWarnings("rawtypes")
	private final List<FormField> fields = Arrays.asList(
			new StringTextFormField(P_ISSUER, messages.issuerLabel(), messages.issuerHelp(), true),
			new PasswordFormField(P_HMAC_SIGNING_SECRET,
					messages.hmacSecretLabel(), messages.hmacSecretHelp(MIN_SECRET_LENGTH),
					true, ".{" + MIN_SECRET_LENGTH + ",}"
			)
	);

	@Override
	public CapabilityType type() {
		return JWTAPIKeyCapability.TYPE;
	}

	@Override
	public String name() {
		return messages.name();
	}

	@Override
	protected String renderAbout() {
		return messages.about();
	}

	@Override
	@SuppressWarnings("rawtypes")
	public List<FormField> formFields() {
		return fields;
	}

	public JWTAPIKeyConfig createAPIKeyConfig(Map<String, String> params) {
		byte[] hmacKeyBytes = params.get(P_HMAC_SIGNING_SECRET).getBytes(StandardCharsets.UTF_8);

		return new JWTAPIKeyConfig(
				params.get(P_ISSUER),
				hmacKeyBytes.length >= 512/8 ? HMAC512(hmacKeyBytes) :
				hmacKeyBytes.length >= 384/8 ? HMAC384(hmacKeyBytes) :
				/*           length >= 256/8 */HMAC256(hmacKeyBytes)
		);
	}

}
