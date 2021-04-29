# api-security
一个基于RSA+AES的API签名、加密、解密的框架

## 缘起
我经常会写一些小项目放到阿里云上运行，有些是对外开放的项目，虽然访问的人数不多，但是安全问题还是需要考虑的。于是我就想给自己写的小项目加上API加密功能。

一个安全的API应该具有以下几个安全功能：防篡改、防重放攻击、防中间人攻击。

一般情况下，网站使用https，再加个请求参数签名的功能就能满足安全需要了。但是在浏览器控制台，接口的入参和返回结果依然是明文的，如果遇到中间人攻击，数据还是有泄露的可能。
所以我就想把请求参数和返回结果都加密。

## 实现思路
具体的实现思路和demo项目我都记录在我的这几篇博客中了：

[博客地址](https://blog.fengxiuge.top/categories/API%E5%8A%A0%E5%AF%86/)

## 使用方法

### pom 文件中引入 Jar 包

```xml
<dependency>
     <groupId>com.fxg</groupId>
     <artifactId>api-security</artifactId>
     <version>1.0-SNAPSHOT</version>
</dependency>
```



### 在 application.yml 中添加如下配置

```yaml
api:
  security:
    open: true            ##总开关
    check-sign: true      ##是否验证签名和重放请求
    timeout: 300000     ##请求过期时间
    show-log: true        ##是否打印日志
    public-key: MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMbFUgBEsev1lURtNFgfr0jtz4IDJ6MEyIkA2WMG57bPfSsT4Pei7bxsXUCyMTXQbaxV0SThX802gxrpTEBAbJsCAwEAAQ==
    private-key: MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAxsVSAESx6/WVRG00WB+vSO3PggMnowTIiQDZYwbnts99KxPg96LtvGxdQLIxNdBtrFXRJOFfzTaDGulMQEBsmwIDAQABAkEAqG6gM9YCJn5txBP9nQcMU3IgunzN45e0DlQH4aACTac6JHPTZAA1STxdgTosdDBhrC1HA2pPlRzCuCAh3MpvgQIhAOxTENdAAiQPspaFWAvGJZhN767g9LFGUVdabvf0mCC7AiEA11HZRiSpICXO2U1MrYsLrTJMHrQQvCM/mOhW4UullaECIDs/7DX7T04ZPW4tilCRYjWYPKJ8tfyII7ah7rZt9YInAiBSdJSY6OcfWXsp+hEYEDxLegxuYZRbB8COBMNoiXiCoQIgMls9U5YPlGQ3ajDUhFACFIUNpGQl8l2faxPy/yRoV6o=
```

public-key 和 private-key 没有默认配置，可以通过网站在线生成，也可以直接使用上面的这个示例配置。

### 在启动类上增加 @EnableSecurity 注解

@EnableSecurity 注解是启动组件的开关注解，必须添加这个注解，相关安全组件才会被注册到系统中。它的主要作用是向spring容器注册下面三个类：

* ApiSignFilter：验证签名的过滤器，主要用来解密 AES 秘钥和验证签名
* DecryptRequestBodyAdvice：用来解密 RequestBody 的 @ControllerAdvice 类
* EncryptResponseBodyAdvice：用来加密 ResponseBody 的 @ControllerAdvice 类

### 增加配置扫描包

修改启动类上的 @SpringBootApplication 注解，增加配置扫描包，如：
@SpringBootApplication(scanBasePackages = {"com.xxx.xxx", "com.fxg.api.security"})
其中 com.xxx.xxx 是你启动类所在包名，com.fxg.api.security 是 api-security 的包名。
这样 spring boot 在启动的时候才后扫描 api-security 包，把响应的组件注入到 Spring 容器中。

## 测试签名、加密、解密功能

### 测试签名功能

在 Controller 中创建一个 Post 方法：

```
	@PostMapping("/sign")
	public String sign(@RequestParam Integer id, @RequestBody User user) {
		logger.info("enter sign method,id:{},user:{}", id, user);
		return "ok";
	}
```



在 PostMan 中创建一个 Post 请求：

```
Params：
id:99

Body:
{"id":"99"}

Headers:
##时间戳
X_TIMESTAMP:1613815735447
##随机字符串
X_NONCE:1613815735447
##encryptAesKey,Rsa加密后的Aes秘钥（下面这个的原文是：VuL0fSCfWeQzl7yUcYasqhOLlO80M365）
X_EAK:Row54E6DJctz4V3OhK3JWj4bmeiOIpZLkq0K8DaHORL7TuflHxwK4Npa6gypcSGH7vh5Zi4mEEor3cR9HlGcgg==
##签名结果
X_SIGN:6448020f50ecfbf135a34e9f8b3fa800

注意事项：
1. 签名结果可以写个 main 方法获取，示例如下：

	public static void main(String[] args) {
		TreeMap<String, String> params = new TreeMap<>();
		params.put("timestamp", "1613815735447");
		params.put("nonce", "1613815735447");
		params.put("aesKey", "VuL0fSCfWeQzl7yUcYasqhOLlO80M365");
		params.put("id", "99");
		params.put("body", "{\"id\":\"99\"}");
		String sign = SignUtil.sign(params);
		System.out.println(sign);
	}
```

发起请求发现返回了463的状态码，后台也打印出了警告信息：*Timestamp validation failed! requestTime:1613815735447, currentTime:1613963122150,timeOut:30000*

说明请求已经过期了，示例中的时间戳 1613815735447 对应的日期是：2021-02-20 18:08:55，距离现在肯定已经超过 5 分钟了。按照后台提示的 currentTime 时间戳，修改请求头中的 X_TIMESTAMP 值，重新计算签名后发起请求即可。

### 测试加密功能

为方便测试可以先将配置项 api.security.check-sign 配置为 false。

在 Controller 中创建以下方法：

```
	@Encrypt
	@GetMapping("/encrypt")
	private User encrypt() {
		User user = new User();
		user.setNickName("encrypt");
		logger.info("enter encrypt method,return user:{}", user);
		return user;
	}
```

在 PostMan 创建一个 Get 请求，直接发起请求即可。

### 测试解密功能

为方便测试可以先将配置项 api.security.check-sign 配置为 false。

在 Controller 中创建以下方法：

```
	@Decrypt
	@PostMapping("/decrypt")
	private User decrypt(@RequestBody User user) {
		logger.info("enter decrypt method,param user:{}", user);
		user.setId(1);
		logger.info("enter decrypt method,return user:{}", user);
		return user;
	}
```

在 PostMan 创建一个 Post 请求，将测试加密功能时返回的加密结果复制到请求的 body 中，直接发起请求即可。



## 总结

其实在生产中， API 的安全校验也好、数据加解密也好，一般在网关层，基本都是放在一处完成。请求进内部服务的 Controller 前就把这些都做完了，内部服务也不应该关心这些检验和加解密。所以这个组件把解密和加密分别放在 RequestBodyAdvice 和 ResponseBodyAdvice 中，然后用注解来控制的方式有点花架子的意思，，，实际作用不大，但是在个人的单体小项目中和是很好的，很灵活，目前 [小链家](https://house.fengxiuge.top/) 和小程序郑房曲线中都采用了这个组件。