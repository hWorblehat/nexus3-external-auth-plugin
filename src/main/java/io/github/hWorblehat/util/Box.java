package io.github.hWorblehat.util;

import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public interface Box<T> extends Supplier<T> {

	void set(T value);

	static <T> Box<T> of(Supplier<T> getter, Consumer<T> setter) {
		return new Box<T>() {
			@Override
			public void set(T value) {
				setter.accept(value);
			}

			@Override
			public T get() {
				return getter.get();
			}
		};
	}

	static <T> Box<T> ofNonNull(Supplier<T> getter, Consumer<T> setter) {
		return of(getter, v -> setter.accept(requireNonNull(v)));
	}

	static <T> Box<T> ofMapEntry(Map.Entry<?, T> mapEntry) {
		return of(mapEntry::getValue, mapEntry::setValue);
	}

	static <T> Box<T> ofNonNullMapEntry(Map.Entry<?, T> mapEntry) {
		return ofNonNull(mapEntry::getValue, mapEntry::setValue);
	}

}
