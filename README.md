# CSRF跨站点攻击原理与应对

####  背景

随着互联网的高速发展，信息安全问题已经成为企业最为关注的焦点之一，而前端又是引发企业安全问题的高		危据点。前端的安全问题除了XSS，CSRF，又常常遭遇网络挟持，安全问题层出不穷。虽然，浏览器自身也在不断进化，引入CSP等，refer等来加强网络的安全性，但是，仍然存在很多潜在的威胁。这篇文章主要来分析一下CSRF以及其应对措施。

####   CSRF攻击介绍
 CSRF(Cross Site Request Forgery, 跨站域请求伪造)是一种网络的攻击方式，它在2007年曾被列入互联网20大安全隐患。即便是大名鼎鼎的Gmail，在2007年也存在着CSRF漏洞，从而被黑客攻击，导致大量的损失。

####   CSRF攻击实例
CSRF可以在受害者毫不知情的情况，以受害者名义发出受保护的请求给被攻击的站点，从而进行一些涉及受害人财产损失等敏感操作。

例如，小王有一天百无聊赖刷着Gmail，突然收到了一封比特币账户重置密码的邮件，小王没有在意，以为是别人填错邮箱了。然后小王又收到一封邮件，“屠龙宝刀，点击就送”，这次小王按捺不住心中的喜悦，点击了进去，发现只是一个空白页面，小王有些失落，但也没有在意。

又过了几天，小王登录自己的比特币账户，发现自己那几个比特币居然没了。小王回想起那天收到的奇怪的链接，于是重新打开了那个空白页，看了下源码。

	<form method="POST" action="https://mail.google.com/mail/h/ewt1jmuj4ddv/?v=prf" 			enctype="multipart/form-data">
	<input type="hidden" name="cf2_emc" value="true"/>
	<input type="hidden" name="cf2_email" value="hacker@hakermail.com"/>
	.....
	<input type="hidden" name="irf" value="on"/>
	<input type="hidden" name="nvp_bu_cftb" value="Create Filter"/>
	</form>
	<script>
	document.forms[0].submit();
	</script>
这个页面只要一打开，就会向Gmail发送一个POST的请求，把自己的邮件全部转给hacker@hakermail.com这个账户。所以黑客有了重置密码的验证码，就更改了小王比特币账户的密码，顺理成章的转走了小王的财产。

这便是一个结合了社会工程学和CSRF攻击的经典案例，首先黑客锁定小王的相关信息，如比特币账户注册邮箱，以及小王的兴趣点，对“屠龙宝刀”感兴趣，然后针对性的发送CSRF攻击邮件，诱使小王点击，从而顺利完成一次攻击。

####   CSRF攻击方式

 1. GET类型的CSRF
GET类型的CSRF利用非常简单，只需要一个HTTP请求，一般会这样利用：

```html

<img src="http://bank.example/withdraw?amount=10000&for=hacker" >

```

受害者只要访问这个含img的页面后，浏览器会自动向” [http://bank.example/withdraw?amount=10000&for=hacker](http://bank.example/withdraw?amount=10000&for=hacker)”发出一次Http请求。Bank.example就会收到包含受害者登录信息的一次跨域请求。

 

2. Post类型的CSRF
这种类型的CSRF利用起来通常使用一个自动提交的表单。

```html
<form action="http://bank.example/withdraw" method=POST>
<input type="hidden" name="account" value="xiaoming" />
<input type="hidden" name="amount" value="10000" />
<input type="hidden" name="for" value="hacker" />
</form>
<script> document.forms[0].submit(); </script>
```
用户访问该页面，表单会自动提交，相当于模拟用户完成了一次POST请求。POST
类型攻击通常比GET要求更加严格一点，但仍并不复杂。

3. 链接类型的CSRF
链接类型的CSRF并不常见，比起其他两种用户打开页面就中招的情况，这种需要
用户点击链接才会触发。这种类型通常是在论坛中发布的图片中嵌入恶意链接，或者以
广告的形式诱导用户中招。代码略过。

####   CSRF攻击特点:

 - 攻击发起一般是在第三方网站，而不是被攻击网站。被攻击的网站无法防止攻击的发生。
 - 攻击利用受害者在被攻击网站已经登录的特点，冒充受害者提交操作，而不是直接窃取数据。
 - 整个过程攻击者并不能获取受害者的登录凭证，仅仅是”冒用”。
 - 跨站点请求可以用各种方式，图片URL，超链接等等，可能发生在本域，如直接嵌入在论坛的某个图片链接，某个博客文章包含的一个超链接等。也可能在外域。因此难以进行追踪。

CSRF通常是跨域的，但是本域也有，如可以发图和链接的论坛等，这类攻击更加危险。
####   CSRF防护策略:
了解了CSRF的攻击特点之后，我们便可以进行针对性的预防。正所谓知己知彼，百战不殆，不管是在白帽预防方面需要了解攻击的原理以及发起特点，如果是在黑帽攻击领域，阅读所攻击框架的源码，也能帮助我们更好的进行漏洞挖掘。

上文介绍了CSRF两个很重要特点：

 - 通常发生在第三方网站。
 - 只能冒用用户凭证，不能获取。

那么我们可以制定针对性的解矫方案，对于第一种，我们可以对请求域进行限制，阻止
不明外域的访问。**同源检测，Samesite Cookie。**

对于第二种，我们附加一些请求条件，只有同域才能获取到的一些信息。CSRF TOKEN，双重Cookie验证。

 - **同源检测**
既然CSRF大多数攻击来源自外域，那么我们就可以直接禁止外域对我们发起请
求。那么如何确认一个请求是否来源于外域呢。
在HTTP协议中，一般请求会包含两个header，用来标记来源域名：
 - **Origin header**
 - **Referer header**

**Origin header来确定来源域名**

我们可以通过判断Origin header来确认来源域名即可。但是Origin header在下面有
两种情况下是无效的。
IE11的同源策略，IE11不会再跨站CORS请求上加上Origin标志，Referer是唯一标识。关于IE11的问题可以参考[https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy#IE_Exceptions](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy#IE_Exceptions)。

302重定向，在302重定向后Origin不包含在重定向的请求中，因为Origin可能  会被认为是其他来源的敏感信息。对于302重定向，因为都是重定向到新的服务器URL，  不想将Origin泄漏到新的服务器上。

**Referer header****来确定域名**

现在大部分防止CSRF都是使用的Referer header来解决的。

对于ajax请求，图片等资源请求，Referer为发起请求的页面地址，对于页面跳转， Referer是打开页面历史记录的前一个页面地址。因此我们使用Referer中链接的域名即  可。

关于Referer相关策略以及资料这里不再赘述，请参考W3C制定的Referrer Policy 草案。现代浏览器大部分已经支持这种草案了。

设置Referer有三种方法：

 - 在CSP设置
 - 在页面增加meta标签: 
 
	 	 <meta name="referrer" content="no-referrer|no-referrer-when-downgrade|origin|origin-when-crossorigin|unsafe-url">
 - a标签增加Referral Policy属性
 
		<a href="http://example.com" referrer="no-referrer|origin|unsafe-url">xxx</a>

我们目前使用的是在CSP中指定。

**那么使用Referrer Policy就一定安全吗**？

其实细心的读者已经发现，我们在上述的论述中都提到了一个很重要的东西，就是

浏览器。不管是Origin也好，还是Referer也罢。都是由**浏览器**来进行控制并且支持，

而在IE6等非现代浏览器是不支持Referer的。或者如果某一个报文是由后端发起，或  者中间被篡改，修改了Referer的值（逃避现代浏览器禁止修改referer的机制），那么我们的Referer校验也就形同虚设了。

同源检测的本质是我们把安全校验放在了第三方，也就是浏览器，因此，从严格的  意义上来讲，也就是不安全的。

那么，有没有更安全的预防措施呢？

 2. **CSRF TOKEN**
其实我们从CSRF的另一个特点，就是它只能冒用受害者的凭证，而不能窃取来入手。我们可以要求所有用户请求的时候必须携带一个token，而这个token攻击者  难以获取，这样即可将普通请求和攻击请求区分开来。

CSRF TOKEN防护策略分三个步骤：

 1. 将CSRF TOKEN输出到页面
 我们可以在用户每次登录的时候生成一个唯一的token，在用户登出或者关闭浏览  器的时候销毁该token。该token可以存放在用户的session中。
 2. 前端的每次请求携带该token
 在前端的请求提交时，在url后缀和请求报文的头部添加该token。
 4. 后端对所有请求校验该token
如果请求不包含该token或者token错误，我们便认为该请求是有问题的。


后端java代码示例：
代码源自[IBM developerworks CSRF]：
[https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/](https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/)

**分布式系统：**

对于分布式系统而言，每个用户都生成这样一个token是一笔开销，而且在集群环境下，由于请求被nginx进行路由，所以session存在于各个单体机器中。所以在分布式环境下使用session存储csrf token可能会失效。在分布式环境下建议采用redis进行公共存储。
 
 3. **双重cookie校验**
在会话中存储CSRF TOKEN压力比较大，而且比较繁琐。那么我们可以利用攻击者无法获取cookie的特点，在前端进行提交时，强制使用cookie中的某个值。

双重cookie采用以下的流程：

 1. 在用户访问网站页面时，向请求域名注入一个cookie，内容为随机字符串。
 2. 在前端向后端发起请求时，取出Cookie，并且添加到url参数中。
 3. 在后端接口验证时，验证cookie中的字段与URL参数是否一致，不一致则拒绝。

当然，此方法并没有大规模应用，其在大型网站的安全性没有CSRF TOKEN的高，  原因如下。在大型系统中，有多个子域名，那么主域名和子域名共用一个cookie以及  对cookie修改权限可能会有问题。如果子域名没有足够权限修改主域名的cookie那么  也就无法完成双重cookie校验。

双重cookie的总结：
优点

 - **实现起来相对简单**
 - **对服务器压力较小**

缺点：

 - **无法做到多子域的隔离**
 - **cookie中注入其他的字段**
 - **如果有其他漏洞，如XSS，cookie被注入，那么该方式失效**
 - **为了保证cookie的传输安全，最好切换到整站Https**

####   总结:
关于csrf的防御：

 - **Csrf自动防御-同源检测**
 - **Csrf主动防御-csrf token，双重cookie校验。**

关于csrf特点：

 - **大多数来源外域**
 - **无法窃取用户cookie**

为了更好的防御CSRF，最佳实践应该是结合上面总结的防御措施方式中的优缺点来综合考虑，结合当前Web应用程序自身的情况做合适的选择，才能更好的预防CSRF的发生。

本文参考美团技术团队的文章：[https://www.freebuf.com/articles/web/186880.html](https://www.freebuf.com/articles/web/186880.html)
