package io.github.hWorblehat.nexus3.auth.jwt.apikey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.github.hWorblehat.nexus3.auth.external.ExternalAuthRealm;
import io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal;
import io.github.hWorblehat.nexus3.auth.external.ExternalUserManager;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.authc.apikey.ApiKeyStore;
import org.sonatype.nexus.security.user.User;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.*;
import java.util.Map.Entry;

import static io.github.hWorblehat.nexus3.auth.external.ExternalPrincipal.asExternal;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

@Named
@Singleton
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class JWTAPIKeys {
	private static final Logger LOGGER = LoggerFactory.getLogger(JWTAPIKeys.class);

	private static final String DOMAIN = "jwtapikey";
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	private static final String REAL_ISSUER_CLAIM = "real_iss";
	private static final String PRINCIPALS_CLAIM = "principals";
	private static final String KEY_ID_CLAIM = "key_id";

	private final ApiKeyStore keyStore;
	private final ExternalUserManager externalUserManager;

	public String create(PrincipalCollection principals, String key, JWTAPIKeyConfig config) {
		String jwt = generateJWT(principals, key, config);
		PrincipalCollection user = forStorage(principals);
		Set<String> keys = new TreeSet<>();
		Collections.addAll(keys, load(user));
		if(keys.add(key)) {
			if(keys.size() > 1) {
				delete(user);
			}
			store(user, keys);
		} else {
			LOGGER.info("API key ID '{}' already exists.", key);
		}
		return jwt;
	}

	public List<String> list(PrincipalCollection principals) {
		return Arrays.asList(load(forStorage(principals)));
	}

	public boolean delete(PrincipalCollection principals, String key) {
		PrincipalCollection user = forStorage(principals);
		String[] keysArray = load(user);
		List<String> keys = new ArrayList<>(keysArray.length);
		Collections.addAll(keys, keysArray);
		if(keys.remove(key)) {
			delete(user);
			if(!keys.isEmpty()) {
				store(user, keys);
			}
			return true;
		} else {
			return false;
		}
	}

	private String[] load(PrincipalCollection principals) {
		char[] keysChars = keyStore.getApiKey(DOMAIN, principals);
		return keysChars != null ? new String(keysChars).split(";") : EMPTY_STRING_ARRAY;
	}

	private void update(PrincipalCollection principals, Iterable<? extends CharSequence> keys) {
		delete(principals);
		store(principals, keys);
	}

	private void delete(PrincipalCollection principals) {
		keyStore.deleteApiKey(DOMAIN, principals);
	}

	private void store(PrincipalCollection principals, Iterable<? extends CharSequence> keys) {
		keyStore.persistApiKey(DOMAIN, principals, String.join(";", keys).toCharArray());
	}

	@Nullable
	public PrincipalCollection toPrincipalCollection(DecodedJWT jwt) {
		if(jwt != null) {
			String issuer = jwt.getClaim(REAL_ISSUER_CLAIM).asString();
			SimplePrincipalCollection principals = new SimplePrincipalCollection();
			if(issuer != null) {
				principals.add(new ExternalPrincipal(issuer, jwt.getSubject(),
						externalUserManager.findBySubject(jwt.getSubject()).map(User::getUserId).orElse(null)
				), ExternalAuthRealm.NAME);
			} else {
				for(Entry<String, ?> ent : jwt.getClaim(PRINCIPALS_CLAIM).asMap().entrySet()) {
					principals.addAll((List<?>) ent.getValue(), ent.getKey());
				}
			}
			String keyId = jwt.getClaim(KEY_ID_CLAIM).asString();
			if(list(principals).contains(keyId)) {
				return principals;
			} else {
				LOGGER.debug("Key ID '{}' appears to no longer be valid for {}",
						keyId, principals.getPrimaryPrincipal());
			}
		}
		return null;
	}

	private PrincipalCollection forStorage(PrincipalCollection principals) {
		ExternalPrincipal p = asExternal(principals);
		if(p != null) {
			principals = new SimplePrincipalCollection(p.getSubject(), ExternalAuthRealm.NAME);
		}
		return principals;
	}

	private String generateJWT(PrincipalCollection principals, String key, JWTAPIKeyConfig config) {
		Date now = new Date();

		JWTCreator.Builder builder = JWT.create()
				.withIssuer(config.getIssuer())
				.withAudience(config.getAudience())
				.withIssuedAt(now)
				.withNotBefore(now)
				.withClaim(KEY_ID_CLAIM, key);

		ExternalPrincipal ext = asExternal(principals);
		if(ext != null) {
			builder.withSubject(ext.getSubject())
					.withClaim(REAL_ISSUER_CLAIM, ext.getIssuer());
		} else {
			Map<String, List<String>> principalsMap = principals.getRealmNames().stream().collect(toMap(
					identity(),
					r -> ((Collection<?>) principals.fromRealm(r)).stream().map(Object::toString).collect(toList())
			));
			builder.withSubject(principals.getPrimaryPrincipal().toString())
					.withClaim(PRINCIPALS_CLAIM, principalsMap);
		}

		return builder.sign(config.getAlgorithm());
	}

}
