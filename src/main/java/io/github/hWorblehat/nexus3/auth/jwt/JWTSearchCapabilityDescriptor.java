package io.github.hWorblehat.nexus3.auth.jwt;

import org.apache.http.HttpHeaders;
import org.sonatype.goodies.i18n.I18N;
import org.sonatype.goodies.i18n.MessageBundle;
import org.sonatype.nexus.capability.CapabilityDescriptorSupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.StringTextFormField;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.github.hWorblehat.nexus3.auth.jwt.JWTSearchCapability.*;
import static java.util.Collections.unmodifiableSet;
import static org.sonatype.nexus.capability.CapabilityType.capabilityType;

@Named
@Singleton
public class JWTSearchCapabilityDescriptor extends CapabilityDescriptorSupport<Void> {

	private interface Messages extends MessageBundle {

		@DefaultMessage("JWT extract header")
		String name();

		@DefaultMessage("Looks for JSON web tokens on an HTTP request header for use in authentication.")
		String about();

		@DefaultMessage("Header")
		String headerLabel();

		@DefaultMessage("The HTTP header on which to look for a JWT")
		String headerHelp();

		@DefaultMessage("Extraction RegEx")
		String patternLabel();

		@DefaultMessage("A regular expression used to recognize and extract the JWT from the header's value. " +
				"Must contain 1 capturing group. Use '%s' to indicate a string matching a JWT.")
		String patternHelp(String jwtRegexPlaceholder);

	}

	private final CapabilityType type = capabilityType(JWTSearchCapability.NAME);
	private final Messages messages = I18N.create(Messages.class);
	private final Set<String> uniqueProperties = unmodifiableSet(new HashSet<>(Arrays.asList(
		P_HEADER, P_PATTERN
	)));

	@SuppressWarnings("rawtypes")
	private final List<FormField> fields = Arrays.asList(
			new StringTextFormField(P_HEADER, messages.headerLabel(), messages.headerHelp(), true)
					.withInitialValue(HttpHeaders.AUTHORIZATION),
			new StringTextFormField(P_PATTERN, messages.patternLabel(), messages.patternHelp(JWT_REGEX_PLACEHOLDER), true)
					.withInitialValue("Bearer (" + JWT_REGEX_PLACEHOLDER + ")")
	);

	@Override
	public CapabilityType type() {
		return type;
	}

	@Override
	public String name() {
		return messages.name();
	}

	@Override
	protected String renderAbout() {
		return messages.about();
	}

	@SuppressWarnings("rawtypes")
	@Override
	public List<FormField> formFields() {
		return fields;
	}

	@Override
	protected Set<String> uniqueProperties() {
		return uniqueProperties;
	}
}
