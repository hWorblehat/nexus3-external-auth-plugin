package com.github.hWorblehat.jwt;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.hWorblehat.util.HttpResource;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.function.IOSupplier;
import org.apache.http.client.HttpClient;
import org.apache.http.entity.ContentType;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
public final class PublicKeyProvider {

	private static final TypeReference<Map<String, Object>> MAP_OF_OBJECT = new TypeReference<Map<String, Object>>(){};

	private final IOSupplier<Map<String, PublicKey>> keyCache;
	private final RSAPublicKeyProvider rsaProvider = new RSAPublicKeyProvider();
	private final ECDSAPublicKeyProvider ecdsaProvider = new ECDSAPublicKeyProvider();

	public PublicKeyProvider(Map<String, PublicKey> keyCache) {
		this(() -> keyCache);
	}

	@Nullable
	public PublicKey getPublicKey(String keyId) {
		try {
			return keyCache.get().get(keyId);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public RSAKeyProvider ofRSA() {
		return rsaProvider;
	}

	public ECDSAKeyProvider ofECDSA() {
		return ecdsaProvider;
	}

	public static PublicKeyProvider fromJwksUri(ObjectMapper mapper, HttpClient httpClient, URI jwksUri) {
		return fromJwksUri(mapper, httpClient, () -> jwksUri);
	}

	public static PublicKeyProvider fromJwksUri(ObjectMapper mapper, HttpClient httpClient, IOSupplier<URI> jwksUri) {
		return new PublicKeyProvider(HttpResource.builder()
				.withHttpClient(httpClient)
				.withURI(jwksUri)
				.withEntityContentHandler(content -> parseJwks(mapper, content))
				.withAcceptContentType(ContentType.APPLICATION_JSON)
				.build()
				.withCaching()
		);
	}

	private static Map<String, PublicKey> parseJwks(ObjectMapper mapper, InputStream content) throws IOException {
		JsonNode json = mapper.readTree(content);
		JsonNode keysJson = json.get("keys");
		Map<String, PublicKey> keys = new HashMap<>(keysJson.size());
		try {
			for (JsonNode elem : keysJson) {
				Jwk jwk = Jwk.fromValues(mapper.convertValue(elem, MAP_OF_OBJECT));
				keys.put(jwk.getId(), jwk.getPublicKey());
			}
		} catch (InvalidPublicKeyException e) {
			throw new IOException(e);
		}
		return keys;
	}

	@RequiredArgsConstructor
	private class RSAPublicKeyProvider implements RSAKeyProvider {

		@Override
		public RSAPublicKey getPublicKeyById(String s) {
			return (RSAPublicKey) PublicKeyProvider.this.getPublicKey(s);
		}

		@Override
		public RSAPrivateKey getPrivateKey() {
			return null;
		}

		@Override
		public String getPrivateKeyId() {
			return null;
		}
	}

	@RequiredArgsConstructor
	private class ECDSAPublicKeyProvider implements ECDSAKeyProvider {

		@Override
		public ECPublicKey getPublicKeyById(String s) {
			return (ECPublicKey) PublicKeyProvider.this.getPublicKey(s);
		}

		@Override
		public ECPrivateKey getPrivateKey() {
			return null;
		}

		@Override
		public String getPrivateKeyId() {
			return null;
		}
	}

}
