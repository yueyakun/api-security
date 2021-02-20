package com.fxg.api.security.util;

import org.springframework.util.Base64Utils;

public class Base64Util {

	/**
	 * Decoding to binary
	 *
	 * @param base64 base64
	 * @return byte
	 * @throws Exception Exception
	 */
	public static byte[] decode(String base64) {
		return Base64Utils.decodeFromString(base64);
	}


	/**
	 * Binary encoding as a string
	 *
	 * @param bytes byte
	 * @return String
	 * @throws Exception Exception
	 */
	public static String encode(byte[] bytes) {
		return new String(Base64Utils.encode(bytes));
	}


	/**
	 * String encoding as a string
	 * @param str
	 * @return
	 * @throws Exception
	 */
	public static String encode(String str) {
		return new String(Base64Utils.encode(str.getBytes()));
	}
}
