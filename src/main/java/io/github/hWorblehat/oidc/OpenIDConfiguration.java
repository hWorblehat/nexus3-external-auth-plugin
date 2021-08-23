package io.github.hWorblehat.oidc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hWorblehat.util.HttpResource;
import io.github.hWorblehat.util.HttpUtil;
import lombok.Value;
import org.apache.http.client.HttpClient;

import java.net.URI;

import static java.util.Objects.requireNonNull;

@Value
@JsonIgnoreProperties(ignoreUnknown = true)
public class OpenIDConfiguration {

	URI tokenEndpoint;
	URI jwksUri;
	String issuer;

	@JsonCreator
	@JsonIgnoreProperties(ignoreUnknown = true)
	public OpenIDConfiguration(
			@JsonProperty(value = "token_endpoint", required = true) URI tokenEndpoint,
			@JsonProperty(value = "jwks_uri", required = true) URI jwksUri,
			@JsonProperty(value = "issuer", required = true) String issuer
	) {
		this.tokenEndpoint = requireNonNull(tokenEndpoint);
		this.jwksUri = requireNonNull(jwksUri);
		this.issuer = requireNonNull(issuer);
	}

	public static HttpResource<OpenIDConfiguration> fromDocumentURI(
			HttpClient httpClient,
			ObjectMapper objectMapper,
			URI documentURI
	) {
		return HttpResource.builder()
				.withHttpClient(httpClient)
				.withURI(documentURI)
				.withJsonParser(objectMapper, OpenIDConfiguration.class)
				.build();
	}

	public static HttpResource<OpenIDConfiguration> fromIssuerURI(
			HttpClient httpClient,
			ObjectMapper objectMapper,
			URI issuerURI
	) {
		return fromDocumentURI(httpClient, objectMapper,
				HttpUtil.ensureTrailingSlash(issuerURI).resolve(".well-known/openid-configuration"));
	}

}
