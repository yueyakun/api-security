package com.fxg.api.security.wrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;

/**
 * 由于request数据读取一次就无法读取，因此通过包装类来解决
 */
public class RequestWrapper extends HttpServletRequestWrapper {
	private final String body;

	private static final Logger logger = LoggerFactory.getLogger(RequestWrapper.class);

	public RequestWrapper(HttpServletRequest request) {
		/*
		 * 由于继承了HttpServletRequestWrapper，HttpServletRequestWrapper又继承了ServletRequestWrapper，
		 * ServletRequestWrapper中有一个private ServletRequest request;
		 * 也就是将原来的request做了一个备份，具体读到的数据放在body中
		 */
		super(request);
		StringBuilder stringBuilder = new StringBuilder();
		BufferedReader bufferedReader = null;
		InputStream inputStream = null;
		try {
			inputStream = request.getInputStream();
			if (inputStream != null) {
				bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
				char[] charBuffer = new char[128];
				int bytesRead;
				while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
					stringBuilder.append(charBuffer, 0, bytesRead);
				}
			}
		} catch (Exception ex) {
			logger.error("过滤器request请求包装时出现异常", ex);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				}
				catch (IOException e) {
					logger.error("过滤器request请求包装关闭流出现异常", e);
				}
			}
			if (bufferedReader != null) {
				try {
					bufferedReader.close();
				}
				catch (IOException e) {
					logger.error("过滤器request请求包装关闭流出现异常", e);
				}
			}
		}
		body = stringBuilder.toString();
		logger.info("过滤器request请求包装结果为：" + body);
	}

	@Override
	public ServletInputStream getInputStream() {
		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
		ServletInputStream servletInputStream = new ServletInputStream() {
			@Override
			public boolean isFinished() {
				return false;
			}
			@Override
			public boolean isReady() {
				return false;
			}
			@Override
			public void setReadListener(ReadListener readListener) {
			}
			@Override
			public int read() {
				return byteArrayInputStream.read();
			}
		};
		return servletInputStream;
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream()));
	}

	public String getBody() {
		return this.body;
	}
}
