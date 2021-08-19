package com.github.hWorblehat.util;

import java.util.Collection;

public final class Util {

	private Util(){}

	public static void closeAll(Collection<AutoCloseable> closeables) throws Exception {
		Exception e = null;
		for(AutoCloseable c : closeables) {
			try {
				c.close();
			} catch (Exception ex) {
				if(e == null) {
					e = ex;
				} else {
					e.addSuppressed(ex);
				}
			}
		}
		if(e != null) {
			throw e;
		}
	}

}
