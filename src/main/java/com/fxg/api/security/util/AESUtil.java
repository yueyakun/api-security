package com.fxg.api.security.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author biehl
 */
public class AESUtil {

	private static final String KEY_ALGORITHM = "AES";
	private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

	/**
	 * AES 加密操作
	 *
	 * @param content 待加密内容
	 * @param appKey  加密appKey
	 * @return 返回Base64转码后的加密数据
	 */
	public static String encrypt(String content, String appKey) throws Exception {

		Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);// 创建密码器

		byte[] byteContent = content.getBytes(StandardCharsets.UTF_8);

		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(appKey.getBytes(), KEY_ALGORITHM));// 初始化为加密模式的密码器

		byte[] result = cipher.doFinal(byteContent);// 加密

		return Base64Util.encode(result);// 通过Base64转码返回

	}

	/**
	 * AES 解密操作
	 *
	 * @param content 待解密内容
	 * @param appKey  加密appKey
	 * @return
	 */
	public static String decrypt(String content, String appKey) {
		try {
			// 实例化
			Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);

			// 使用密钥初始化，设置为解密模式
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(appKey.getBytes(), KEY_ALGORITHM));

			// 执行操作
			byte[] result = cipher.doFinal(Base64Util.decode(content));

			return new String(result, StandardCharsets.UTF_8);
		} catch (Exception ex) {
			Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
		}

		return null;
	}
}