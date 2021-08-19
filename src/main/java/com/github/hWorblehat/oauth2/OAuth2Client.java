package com.github.hWorblehat.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.hWorblehat.util.DelegateBuilderBase;
import com.github.hWorblehat.util.MapNameValuePairIterator;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.function.IOSupplier;
import org.apache.http.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.AbstractResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;

import static java.util.Objects.requireNonNull;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2Client implements Closeable {
	private static final int TOKEN_REQUEST_PARAMS_ESTIMATE = 10;
	private static final HeaderElement[] NO_ELEMENTS = new HeaderElement[0];

	private final HttpClient httpClient;
	private final ObjectMapper objectMapper;
	private final IOSupplier<URI> tokenEndpoint;

	private final String clientId;
	private final String clientSecret;

	private final Closeable toClose;

	ConcurrentMap<Map<String, String>, Future<JsonNode>> tokenRequestMonitorCache = new ConcurrentHashMap<>();

	private final ResponseHandler<JsonNode> tokenResponseHandler = new AbstractResponseHandler<JsonNode>() {
		@Override
		public JsonNode handleEntity(HttpEntity httpEntity) throws IOException {
			try(InputStream body = httpEntity.getContent()) {
				return objectMapper.readTree(body);
			}
		}
	};

	public JsonNode token(Map<String, String> parameters, Set<String> requiredScopes) throws IOException {
		parameters.put("client_id", clientId);
		parameters.put("client_secret", clientSecret);

		parameters.compute("scope", (s, scopes) -> {
			final Set<String> allScopes;
			if(scopes == null) {
				allScopes = requiredScopes;
			} else {
				allScopes = new HashSet<>(requiredScopes);
				Collections.addAll(allScopes, scopes.split(" "));
			}
			return String.join(" ", allScopes);
		});

		FutureTask<JsonNode> task = new FutureTask<>(() -> {
			HttpPost req = new HttpPost(tokenEndpoint.get());
			req.setEntity(new UrlEncodedFormEntity(MapNameValuePairIterator.iterable(parameters)));
			return httpClient.execute(req, this::handleResponse);
		});

		Future<JsonNode> existing = tokenRequestMonitorCache.putIfAbsent(parameters, task);

		try {
			if(existing != null) {
				return existing.get();
			} else {
				task.run();
				tokenRequestMonitorCache.remove(parameters);
				return task.get();
			}
		} catch (ExecutionException e) {
			throw new IOException(e.getMessage(), e.getCause());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException(e);
		}
	}

	private JsonNode handleResponse(HttpResponse response) throws IOException {
		StatusLine statusLine = response.getStatusLine();
		HttpEntity entity = response.getEntity();

		JsonNode details = null;
		IOException decodeException = null;

		Header contentTypeHeader = response.getFirstHeader(CONTENT_TYPE);
		ContentType contentType = contentTypeHeader == null ? null : ContentType.parse(contentTypeHeader.getValue());
		if (contentType != null && contentType.getMimeType().equalsIgnoreCase(APPLICATION_JSON.getMimeType())) {
			try (Reader body = new InputStreamReader(entity.getContent(), contentType.getCharset())) {
				details = objectMapper.readTree(body);
			} catch (IOException e) {
				decodeException = e;
			}
		}

		if(statusLine.getStatusCode() >= 300) {
			IOException ex = details != null && details.has("error")
					? new IOException(String.format("%d/%s: %s", statusLine.getStatusCode(),
					details.get("error").asText(),
					details.has("error_description")
							? details.get("error_description").asText()
							: statusLine.getReasonPhrase()
			))
					: new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
			if(decodeException != null) {
				ex.addSuppressed(decodeException);
			}
			throw ex;
		} else if(decodeException != null) {
			throw decodeException;
		} else {
			return details;
		}
	}

	public static Map<String, String> onBehalfOf(String accessToken) {
		Map<String, String> params = new HashMap<>(TOKEN_REQUEST_PARAMS_ESTIMATE);
		params.put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
		params.put("requested_token_use", "on_behalf_of");
		params.put("assertion", accessToken);
		return params;
	}

	public static Map<String, String> refresh(String refreshToken) {
		Map<String, String> params = new HashMap<>(TOKEN_REQUEST_PARAMS_ESTIMATE);
		params.put("grant_type", "refresh_token");
		params.put("refresh_token", refreshToken);
		return params;
	}

	@Override
	public void close() throws IOException {
		if(toClose != null) {
			toClose.close();
		}
	}

	public static Builder builder() {
		return new Builder();
	}

	public interface IBuilder<B extends IBuilder<B>> {

		B withBorrowedHttpClient(HttpClient httpClient);

		B withOwnedHttpClient(CloseableHttpClient httpClient);

		B withObjectMapper(ObjectMapper objectMapper);

		B withTokenEndpoint(IOSupplier<URI> tokenEndpoint);

		default B withTokenEndpoint(URI tokenEndpoint) {
			requireNonNull(tokenEndpoint);
			return withTokenEndpoint(() -> tokenEndpoint);
		}

		default B withTokenEndpoint(String tokenEndpoint) {
			return withTokenEndpoint(URI.create(tokenEndpoint));
		}

		B withClientId(String clientId);

		B withClientSecret(String clientSecret);

	}

	@NoArgsConstructor(access = AccessLevel.PRIVATE)
	public static final class Builder implements IBuilder<Builder> {
		private HttpClient httpClient;
		private ObjectMapper objectMapper;
		private IOSupplier<URI> tokenEndpoint;
		private String clientId;
		private String clientSecret;
		private Closeable toClose;

		@Override
		public Builder withBorrowedHttpClient(HttpClient httpClient) {
			this.httpClient = httpClient;
			this.toClose = null;
			return this;
		}

		@Override
		public Builder withOwnedHttpClient(CloseableHttpClient httpClient) {
			this.httpClient = httpClient;
			this.toClose = httpClient;
			return this;
		}

		@Override
		public Builder withObjectMapper(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
			return this;
		}

		@Override
		public Builder withTokenEndpoint(IOSupplier<URI> tokenEndpoint) {
			this.tokenEndpoint = tokenEndpoint;
			return this;
		}

		@Override
		public Builder withClientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		@Override
		public Builder withClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		public OAuth2Client build() {
			ObjectMapper objectMapper = this.objectMapper;
			if(objectMapper == null) {
				objectMapper = new ObjectMapper();
			}

			return new OAuth2Client(
					requireNonNull(httpClient),
					objectMapper,
					requireNonNull(tokenEndpoint),
					requireNonNull(clientId),
					requireNonNull(clientSecret),
					toClose
			);
		}
	}

	public interface DelegateBuilder<B extends IBuilder<B>> extends DelegateBuilderBase<B>, IBuilder<B> {

		IBuilder<?> getOAuth2ClientBuilderDelegate();

		@Override
		default B withBorrowedHttpClient(HttpClient httpClient) {
			getOAuth2ClientBuilderDelegate().withBorrowedHttpClient(httpClient);
			return getThis();
		}

		@Override
		default B withOwnedHttpClient(CloseableHttpClient httpClient) {
			getOAuth2ClientBuilderDelegate().withOwnedHttpClient(httpClient);
			return getThis();
		}

		@Override
		default B withObjectMapper(ObjectMapper objectMapper) {
			getOAuth2ClientBuilderDelegate().withObjectMapper(objectMapper);
			return getThis();
		}

		@Override
		default B withTokenEndpoint(IOSupplier<URI> tokenEndpoint) {
			getOAuth2ClientBuilderDelegate().withTokenEndpoint(tokenEndpoint);
			return getThis();
		}

		@Override
		default B withClientId(String clientId) {
			getOAuth2ClientBuilderDelegate().withClientId(clientId);
			return getThis();
		}

		@Override
		default B withClientSecret(String clientSecret) {
			getOAuth2ClientBuilderDelegate().withClientSecret(clientSecret);
			return getThis();
		}

	}

}
