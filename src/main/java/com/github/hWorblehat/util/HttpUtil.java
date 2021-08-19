package com.github.hWorblehat.util;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

import static java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;

public final class HttpUtil {

	private static final DateTimeFormatter RFC_850_DATE_TIME =
			DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss 'GMT'");
	private static final DateTimeFormatter ASC_DATE_TIME_1 = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss yyyy");
	private static final DateTimeFormatter ASC_DATE_TIME_2 = DateTimeFormatter.ofPattern("EEE MMM  d HH:mm:ss yyyy");

	private static final DateTimeFormatter[] HTTPWG_RFC7231_DATE_FROMATS = {
			RFC_1123_DATE_TIME, RFC_850_DATE_TIME, ASC_DATE_TIME_1, ASC_DATE_TIME_2
	};

	private HttpUtil(){}

	public static Instant parseRfc7231DateTime(String dateTimeStr) {
		List<DateTimeParseException> exceptions = new ArrayList<>(HTTPWG_RFC7231_DATE_FROMATS.length);
		for(DateTimeFormatter f: HTTPWG_RFC7231_DATE_FROMATS) {
			try {
				return Instant.from(f.parse(dateTimeStr));
			} catch (DateTimeParseException e) {
				exceptions.add(e);
			}
		}
		DateTimeParseException e = exceptions.remove(0);
		for(Throwable t: exceptions) {
			e.addSuppressed(t);
		}
		throw e;
	}

	public static Optional<Instant> getCacheExpiry(HttpResponse resp, Instant now) throws ClientProtocolException {
		Header cacheControl = resp.getLastHeader(HttpHeaders.CACHE_CONTROL);
		if(cacheControl!=null) {
			for(HeaderElement elem : cacheControl.getElements()) {
				if ("max-age".equals(elem.getName())) {
					try {
						return Optional.of(now.plusSeconds(Integer.parseInt(elem.getValue())));
					} catch (NumberFormatException e) {
						throw badHeader(HttpHeaders.CACHE_CONTROL, e);
					}
				}
			}
		}

		Header expires = resp.getLastHeader(HttpHeaders.EXPIRES);
		if(expires != null) {
			try {
				return Optional.of(parseRfc7231DateTime(expires.getValue()));
			} catch (DateTimeParseException e) {
				throw badHeader(HttpHeaders.EXPIRES, e);
			}
		}

		return Optional.empty();
	}

	private static ClientProtocolException badHeader(String headerName, Throwable cause) {
		return new ClientProtocolException(headerName + " header was malformed.", cause);
	}

	public static String ensureTrailingSlash(String uri) {
		if(!uri.endsWith("/")) {
			uri += "/";
		}
		return uri;
	}

	public static URI ensureTrailingSlash(URI uri) {
		if(!uri.getPath().endsWith("/")) {
			try {
				uri = new URI(
						uri.getScheme(),
						uri.getUserInfo(),
						uri.getHost(),
						uri.getPort(),
						ensureTrailingSlash(uri.getPath()),
						uri.getQuery(),
						uri.getFragment()
				);
			} catch (URISyntaxException e) {
				throw new IllegalArgumentException("Invalid URI given.", e);
			}
		}
		return uri;
	}

}
