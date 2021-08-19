package com.github.hWorblehat.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.function.IOFunction;
import org.apache.commons.io.function.IOSupplier;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class HttpResource<T> implements IOSupplier<T> {

	private final HttpClient httpClient;
	private final IOSupplier<URI> uriSupplier;
	private final String acceptContentType;
	private final ResponseHandler<T> responseHandler;

	@Override
	public T get() throws IOException {
		return responseHandler.handleResponse(request());
	}

	public CachedHttpResource<T> withCaching() {
		return new CachedHttpResource<>(this);
	}

	private HttpResponse request() throws IOException {
		URI uri = uriSupplier.get();
		HttpGet req = new HttpGet(uri);
		req.addHeader(HttpHeaders.ACCEPT, acceptContentType);

		HttpResponse resp = httpClient.execute(req);
		StatusLine statusLine = resp.getStatusLine();
		HttpEntity entity = resp.getEntity();

		if (statusLine.getStatusCode() >= 300) {
			EntityUtils.consume(entity);
			throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
		}

		if (entity == null) {
			throw new ClientProtocolException("HTTP response body missing.");
		}

		return resp;
	}

	public static Builder builder() {
		return new Builder();
	}

	@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
	public static class CachedHttpResource<T> implements IOSupplier<T> {
		private final HttpResource<T> delegate;

		private T cachedValue = null;
		private Instant expiry = Instant.EPOCH;

		@Override
		public T get() throws IOException {
			Instant now = Instant.now();
			T value = cachedValue;
			if (value == null || now.isAfter(expiry)) {
				HttpResponse resp = delegate.request();

				value = delegate.responseHandler.handleResponse(resp);
				Instant expiry = HttpUtil.getCacheExpiry(resp, now)
						.orElseGet(() -> now.plus(1, ChronoUnit.HOURS));

				cachedValue = value;
				this.expiry = expiry;
			}
			return value;
		}
	}

	public interface IBuilder<B extends IBuilder<B>> {

		B withHttpClient(HttpClient httpClient);

		B withURI(IOSupplier<URI> uriSupplier);

		default B withURI(URI uri) {
			Objects.requireNonNull(uri);
			return withURI(() -> uri);
		}

		B withAcceptContentType(String contentType);

		default B withAcceptContentType(ContentType contentType) {
			return withAcceptContentType(contentType.getMimeType());
		}

	}

	@NoArgsConstructor(access = AccessLevel.PRIVATE)
	public static class Builder implements IBuilder<Builder> {
		private HttpClient httpClient;
		private IOSupplier<URI> uriSupplier;
		private String acceptContentType;

		@Override
		public Builder withHttpClient(HttpClient httpClient) {
			this.httpClient = httpClient;
			return this;
		}

		@Override
		public Builder withURI(IOSupplier<URI> uriSupplier) {
			this.uriSupplier = uriSupplier;
			return this;
		}

		@Override
		public Builder withAcceptContentType(String contentType) {
			this.acceptContentType = contentType;
			return this;
		}

		public <T> TypedBuilder<T> withResponseHandler(ResponseHandler<T> responseHandler) {
			return new TypedBuilder<>(this, Objects.requireNonNull(responseHandler));
		}

		public <T> TypedBuilder<T> withEntityHandler(IOFunction<HttpEntity, T> entityHandler) {
			Objects.requireNonNull(entityHandler);
			return withResponseHandler(resp -> entityHandler.apply(resp.getEntity()));
		}

		public <T> TypedBuilder<T> withEntityContentHandler(IOFunction<InputStream, T> entityContentHandler) {
			Objects.requireNonNull(entityContentHandler);
			return withEntityHandler(entity -> {
				try(InputStream content = entity.getContent()) {
					return entityContentHandler.apply(content);
				}
			});
		}

		public TypedBuilder<JsonNode> withJsonParser(ObjectMapper objectMapper) {
			Objects.requireNonNull(objectMapper);
			return withAcceptContentType(ContentType.APPLICATION_JSON)
					.withEntityContentHandler(objectMapper::readTree);
		}

		public <T> TypedBuilder<T> withJsonParser(ObjectMapper objectMapper, Class<T> type) {
			Objects.requireNonNull(objectMapper);
			Objects.requireNonNull(type);
			return withAcceptContentType(ContentType.APPLICATION_JSON)
					.withEntityContentHandler(content -> objectMapper.readValue(content, type));
		}

	}

	@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
	public static final class TypedBuilder<T> implements IBuilder<TypedBuilder<T>> {
		private final Builder delegate;
		private final ResponseHandler<T> responseHandler;

		@Override
		public TypedBuilder<T> withHttpClient(HttpClient httpClient) {
			delegate.withHttpClient(httpClient);
			return this;
		}

		@Override
		public TypedBuilder<T> withURI(IOSupplier<URI> uriSupplier) {
			delegate.withURI(uriSupplier);
			return this;
		}

		@Override
		public TypedBuilder<T> withAcceptContentType(String contentType) {
			delegate.withAcceptContentType(contentType);
			return this;
		}

		public HttpResource<T> build() {
			return new HttpResource<T>(
					Objects.requireNonNull(delegate.httpClient, "HTTP client"),
					Objects.requireNonNull(delegate.uriSupplier, "URI supplier"),
					Objects.requireNonNull(delegate.acceptContentType, "'Accept' content type"),
					responseHandler
			);
		}

	}

}
