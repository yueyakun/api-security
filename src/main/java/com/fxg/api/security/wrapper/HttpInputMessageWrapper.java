package com.fxg.api.security.wrapper;

import com.fxg.api.security.annotation.Decrypt;
import com.fxg.api.security.interceptor.AESKeyHandler;
import com.fxg.api.security.util.AESUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.util.StringUtils;

import java.io.*;
import java.util.stream.Collectors;

public class HttpInputMessageWrapper implements HttpInputMessage {


	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	private HttpHeaders headers;
	private InputStream body;
	boolean showLog;


	public HttpInputMessageWrapper(HttpInputMessage inputMessage, Boolean showLog, Decrypt decrypt) throws IOException {

		this.showLog = showLog;
		this.headers = inputMessage.getHeaders();

		String aesKey = AESKeyHandler.get();
		this.log("received aesKey:{}", aesKey);

		if (!StringUtils.hasText(aesKey)) {
			throw new IllegalArgumentException("aesKey is null");
		}

		String content = new BufferedReader(new InputStreamReader(inputMessage.getBody())).lines()
				.collect(Collectors.joining(System.lineSeparator()));

		this.log("Encrypted data received：{}", content);

		String decryptBody;
		// 如果未加密
		if (content.startsWith("{")) {
			// 必须加密
			if (decrypt.required()) {
				logger.error("Not support unencrypted content:{}", content);
				throw new RuntimeException("Not support unencrypted content:" + content);
			}
			this.log("Unencrypted without decryption:{}", content);
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
			this.log("After decryption：{}", decryptBody);
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

	private void log(String template, String message) {
		if (this.showLog) {
			logger.info(template, message);
		}
	}
}
