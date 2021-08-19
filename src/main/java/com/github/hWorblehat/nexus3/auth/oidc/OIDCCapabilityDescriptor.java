package com.github.hWorblehat.nexus3.auth.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.hWorblehat.oidc.IDTokenClaims;
import lombok.RequiredArgsConstructor;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.i18n.I18N;
import org.sonatype.goodies.i18n.MessageBundle;
import org.sonatype.nexus.capability.CapabilityDescriptorSupport;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.StringTextFormField;
import org.sonatype.nexus.formfields.UrlFormField;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.util.*;

import static java.util.Collections.unmodifiableSet;

@Singleton
@Named(OIDCCapabilityDescriptor.NAME)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class OIDCCapabilityDescriptor extends CapabilityDescriptorSupport<Void> {
	private static final Logger LOGGER = LoggerFactory.getLogger(OIDCCapabilityDescriptor.class);

	private interface Messages extends MessageBundle {

		@DefaultMessage("OpenID Connect authentication")
		String name();

		@DefaultMessage("Supports authenticating users with an OpenID Connect identity provider")
		String about();

		@DefaultMessage("Issuer URI")
		String issuerUriLabel();

		@DefaultMessage("The base URI of the OpenID Connect identity provider")
		String issuerUriHelp();

		@DefaultMessage("Client ID")
		String clientIdLabel();

		@DefaultMessage("Client secret")
		String clientSecretLabel();

		@DefaultMessage("The %s of the OpenID Connect service provider client")
		String oidcServiceParamHelp(String param);

		@DefaultMessage("preferred username")
		String preferredUsernameClaim();

		@DefaultMessage("email")
		String emailClaim();

		@DefaultMessage("first name")
		String firstNameClaim();

		@DefaultMessage("last name")
		String lastNameClaim();

		@DefaultMessage("roles")
		String rolesClaim();

		@DefaultMessage("ID token %s claim")
		String claimLabel(String claim);

		@DefaultMessage("The name of the claim to look for for the user's %s on the ID token")
		String claimHelp(String claim);

	}

	public static final String NAME = OIDCCapability.NAME;

	static final String P_ISSUER_URI = "issuer";
	static final String P_CLIENT_ID = "clientId";
	static final String P_CLIENT_SECRET = "clientSecret";
	static final String P_PREFERRED_USERNAME_CLAIM = "preferredUsernameClaim";
	static final String P_EMAIL_CLAIM = "emailClaim";
	static final String P_FIRST_NAME_CLAIM = "firstNameClaim";
	static final String P_LAST_NAME_CLAIM = "lastNameClaim";
	static final String P_ROLES_CLAIM = "rolesClaim";

	private final CapabilityType type = CapabilityType.capabilityType(OIDCCapability.NAME);
	private final Messages messages = I18N.create(Messages.class);
	private final Set<String> uniqueProperties = unmodifiableSet(new HashSet<>(Arrays.asList(
			P_ISSUER_URI, P_CLIENT_ID
	)));

	private final Provider<CloseableHttpClient> httpClientProvider;
	private final ObjectMapper objectMapper = new ObjectMapper();

	@SuppressWarnings("rawtypes")
	private final List<FormField> fields = Arrays.asList(
			new UrlFormField(P_ISSUER_URI, messages.issuerUriLabel(), messages.issuerUriHelp(), true),
			clientParam(P_CLIENT_ID, messages.clientIdLabel()),
			clientParam(P_CLIENT_SECRET, messages.clientSecretLabel()),
			claimField(P_PREFERRED_USERNAME_CLAIM, messages.preferredUsernameClaim(), false)
					.withInitialValue(IDTokenClaims.PREFERRED_USERNAME),
			claimField(P_EMAIL_CLAIM, messages.emailClaim(), true)
					.withInitialValue(IDTokenClaims.EMAIL),
			claimField(P_FIRST_NAME_CLAIM, messages.firstNameClaim(), false),
			claimField(P_LAST_NAME_CLAIM, messages.lastNameClaim(), false),
			claimField(P_ROLES_CLAIM, messages.rolesClaim(), false)
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

	@Override
	@SuppressWarnings("rawtypes")
	public List<FormField> formFields() {
		return fields;
	}

	public OIDCAuthenticator createClient(Map<String, String> params) {
		if(LOGGER.isInfoEnabled()) {
			Map<String, String> paramsCopy = new HashMap<>(params);
			paramsCopy.remove(P_CLIENT_SECRET);
			LOGGER.info("Creating new OpenID Connect client: {}", paramsCopy);
		}

		return OIDCAuthenticator.builder()
				.withOwnedHttpClient(httpClientProvider.get())
				.withObjectMapper(objectMapper)
				.withIssuerURI(params.get(P_ISSUER_URI))
				.withClientId(params.get(P_CLIENT_ID))
				.withClientSecret(params.get(P_CLIENT_SECRET))
				.withEmailClaim(params.get(P_EMAIL_CLAIM))
				.withPreferredUsernameClaim(params.get(P_PREFERRED_USERNAME_CLAIM))
				.withFirstNameClaim(params.get(P_FIRST_NAME_CLAIM))
				.withLastNameClaim(params.get(P_LAST_NAME_CLAIM))
				.withRolesClaim(params.get(P_ROLES_CLAIM))
				.build();
	}

	private StringTextFormField claimField(String paramName, String i18nName, boolean required) {
		return new StringTextFormField(paramName, messages.claimLabel(i18nName), messages.claimHelp(i18nName), required);
	}

	private FormField<String> clientParam(String paramName, String i18NName) {
		return new StringTextFormField(paramName, i18NName, messages.oidcServiceParamHelp(i18NName), true);
	}

	@Override
	protected Set<String> uniqueProperties() {
		return uniqueProperties;
	}
}
