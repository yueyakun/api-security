package com.fxg.api.security.interceptor;

/**
 * 用来向后面的RequestBodyAdvice和ResponseBodyAdvice传递解密的aesKey
 */
public class AESKeyHandler {

	private static ThreadLocal<String> aesKeyThreadLocal = new ThreadLocal<>();

	public static String get() {
		return aesKeyThreadLocal.get();
	}

	public static void set(String aesKey) {
		aesKeyThreadLocal.set(aesKey);
	}

	public static void remove() {
		aesKeyThreadLocal.remove();
	}
}
