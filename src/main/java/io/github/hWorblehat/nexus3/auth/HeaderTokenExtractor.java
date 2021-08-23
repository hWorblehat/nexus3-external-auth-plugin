package io.github.hWorblehat.nexus3.auth;

import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
@EqualsAndHashCode
@ToString
public class HeaderTokenExtractor {

	private final String header;
	private final Pattern extractorPattern;

	@Nullable
	public String extract(HttpServletRequest request) {
		String headerValue = request.getHeader(header);
		if(headerValue != null) {
			Matcher m = extractorPattern.matcher(headerValue);
			if(m.matches()) {
				return m.group(1);
			}
		}
		return null;
	}

}
