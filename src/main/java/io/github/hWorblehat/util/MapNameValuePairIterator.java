package io.github.hWorblehat.util;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.apache.http.NameValuePair;

import java.util.Iterator;
import java.util.Map;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class MapNameValuePairIterator implements Iterator<NameValuePair>, NameValuePair {
	private final Iterator<? extends Map.Entry<?, ?>> delegate;
	private Map.Entry<?, ?> current;

	@Override
	public boolean hasNext() {
		return delegate.hasNext();
	}

	@Override
	public NameValuePair next() {
		current = delegate.next();
		return this;
	}

	@Override
	public String getName() {
		return current.getKey().toString();
	}

	@Override
	public String getValue() {
		return current.getValue().toString();
	}

	public static MapNameValuePairIterator iterator(Map<?, ?> map) {
		return new MapNameValuePairIterator(map.entrySet().iterator());
	}

	public static Iterable<NameValuePair> iterable(Map<?,?> map) {
		return () -> iterator(map);
	}

}
