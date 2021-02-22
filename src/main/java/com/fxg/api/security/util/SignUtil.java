package com.fxg.api.security.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

public class SignUtil {

	private static final String MD5 = "MD5";


	public static String md5(String string) {
		byte[] hash;
		try {
			hash = MessageDigest.getInstance(MD5).digest(string.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("MessageDigest不支持MD5Util", e);
		}
		StringBuilder hex = new StringBuilder(hash.length * 2);
		for (byte b : hash) {
			if ((b & 0xFF) < 0x10)
				hex.append("0");
			hex.append(Integer.toHexString(b & 0xFF));
		}
		return hex.toString();
	}


	/**
	 * md5签名
	 * <p>
	 * 按参数名称升序，将参数值进行连接 签名
	 *
	 * @param params 参数
	 * @return 签名结果字符串
	 */
	public static String sign(TreeMap<String, String> params) {
		StringBuilder paramValues = new StringBuilder();

		for (Map.Entry<String, String> entry : params.entrySet()) {
			paramValues.append(entry.getValue());
		}
		return md5(paramValues.toString());
	}
}
