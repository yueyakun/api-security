package com.fxg.api.security.wrapper;

import com.fxg.api.security.annotation.Decrypt;
import com.fxg.api.security.config.ApiSecurityConfig;
import com.fxg.api.security.util.AESUtil;
import com.fxg.api.security.interceptor.AESKeyHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

public class HttpInputMessageWrapper implements HttpInputMessage {


	private Logger logger = LoggerFactory.getLogger(this.getClass());
	private HttpHeaders headers;
	private InputStream body;


	public HttpInputMessageWrapper(HttpInputMessage inputMessage, ApiSecurityConfig apiSecurityConfig, Decrypt decrypt)
			throws Exception {

		String aesKey = AESKeyHandler.get();
		logger.info("接收到aesKey:{}", aesKey);

		boolean showLog = apiSecurityConfig.isShowLog();

		if (StringUtils.isEmpty(aesKey)) {
			throw new IllegalArgumentException("aesKey is null");
		}

		this.headers = inputMessage.getHeaders();
		String content = new BufferedReader(new InputStreamReader(inputMessage.getBody())).lines()
				.collect(Collectors.joining(System.lineSeparator()));

		if (showLog) {
			logger.info("Encrypted data received：{}", content);
		}

		String decryptBody;
		// 如果未加密
		if (content.startsWith("{")) {
			// 必须加密
			if (decrypt.required()) {
				logger.error("Not support unencrypted content:{}", content);
				throw new RuntimeException("Not support unencrypted content:" + content);
			}
			logger.info("Unencrypted without decryption:{}", content);
			decryptBody = content;
		} else {
			StringBuilder json = new StringBuilder();
			content = content.replaceAll(" ", "+");
			if (!StringUtils.isEmpty(content)) {
				String[] contents = content.split("\\|");
				for (String value : contents) {
					value = AESUtil.decrypt(value, aesKey);
					json.append(value);
				}
			}
			decryptBody = json.toString();
			if (showLog) {
				logger.info("After decryption：{}", decryptBody);
			}
		}

		this.body = new ByteArrayInputStream(decryptBody.getBytes());
	}

	@Override
	public InputStream getBody() {
		return body;
	}

	@Override
	public HttpHeaders getHeaders() {
		return headers;
	}
}
