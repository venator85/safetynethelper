package com.scottyab.safetynet;

import androidx.annotation.NonNull;

class Preconditions {
	static void checkArgument(boolean expression) {
		if (!expression) {
			throw new IllegalArgumentException();
		}
	}

	@NonNull
	static <T> T checkNotNull(final T reference) {
		if (reference == null) {
			throw new NullPointerException();
		}
		return reference;
	}
}