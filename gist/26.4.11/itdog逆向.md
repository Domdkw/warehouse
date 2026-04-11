# itdog 逆向分析：从混淆代码中提取 Token 加密逻辑

## 前言

在 QQ 群里看到有人讨论 itdog 的逆向分析，正好有空就顺手研究了一下。这篇文章记录了整个分析过程，从发现 WebSocket 通信到拆解混淆代码，最后理清 Token 的加密逻辑。

## WebSocket

打开 itdog，输入一个网站域名点击检测，在浏览器开发者工具中观察网络请求。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 183908.png" alt="网络请求分析">

客户端与服务器之间的通信采用的是 WebSocket 协议，而不是普通的 HTTP 请求。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 183940.png" alt="WebSocket 连接">

从图中可以看到，发送给服务器的内容主要包含两个部分，这次分析的重点就是弄清楚这两个部分是如何生成的，尤其是 Token 的生成逻辑。

## 寻找 Token

查看页面源代码，其中主要有用的是前两个。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 184647.png" alt="分析发起程序">

重点关注其他其中两个文件。先打开 HTTP 相关的页面文件，搜索一下页面中包含的这个 ID。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 184030.png" alt="搜索页面 ID">

观察后发现，这个 ID 是动态生成的。每次用户发送检测请求时，服务器端会自动将 ID 补全后随页面一起返回。

如果想把这个功能做成 API 或爬虫，就必须先请求这个页面文件，从中提取出这个 ID。

页面中调用了 `createWebSocket` 函数来建立连接，但这个函数并没有传入 Token 参数，这意味着 Token 应该是在函数内部自行生成的。

## 拆解混淆

代码被混淆了，所有的变量名都变成了毫无意义的字符拼接。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 184206.png" alt="搜索混淆代码">

我的做法是在浏览器控制台中通过 `console.log` 来打印这些混淆后的方法名，从而推断出它们对应的原生方法。

通过对源代码打断点调试，最终在这个位置发现了 WebSocket 实例的创建：

```javascript
'dDcpL': _0x30952f(0x705, '6GGx'),
'QEeHA': _0x30952f(0x1d8, 'NjJ3')
};
_0x3b67ad[_0x30952f(0x692, 'e*U%')](_0x3b67ad['dDcpL'], window) ? (ws = new WebSocket(_0x100925),
ws[_0x30952f(0xc0, '9SW$')] = function() {
    var _0x422e43 = _0x30952f
    , _0x37587e = {
```

`ws[_0x30952f(0xc0, '9SW$')]` 这一步实际上是绑定 WebSocket 的 `onopen` 事件。既然 WebSocket 实例已经创建，接下来就看它有没有调用 `send` 方法。

在逆向混淆代码时，只要看到与 WebSocket 相关的操作都可以多留意一下，善用搜索功能直接搜索 `send` 方法会快很多。

## Token 生成逻辑

经过一番断点调试，找到了关键代码：

```javascript
ws[_0x30952f(0x10c, 'vN[[')] = function() {
    var _0x38871b = _0x30952f;
    if (_0x3b67ad[_0x38871b(0x18e, 'e*U%')](_0x3b67ad[_0x38871b(0xc2, '*ur$')], _0x38871b(0x19b, 'szO)')))
        var _0x3c8517 = {
            'name': '天津',
            'value': _0x4b3b99[0x1],
            'datas': _0x1cad11[0x1]
        };
    else
        ws['send'](_0x3b67ad['OXIIi'](_0x3b67ad[_0x38871b(0x252, 'wGJv')] + _0x42eb74 + _0x3b67ad[_0x38871b(0x7de, 'X^Y#')], _0x3b67ad[_0x38871b(0x30a, 'aG*a')](md5, _0x3b67ad[_0x38871b(0x610, 'UOBG')](_0x42eb74, 'token_20230313000136kwyktxb0tgspm00yo5'), 0x10)) + '\x22}');
}
,
ws[_0x30952f(0x6e8, 'gF@I')] = function(_0x58b418) {
    var _0x5f91e8 = _0x30952f;
```

在控制台中进行验证，确认发送的确实是 ID 和 Token。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 185125.png" alt="控制台验证">

现在需要把混淆代码逐步还原。`_0x38871b(0x30a, 'aG*a')` 这种形式的调用，本质上是一个数字和字符串的组合，返回的是实际的方法名字符串。

将混淆代码还原后，得到以下逻辑：

```javascript
ws['send'](_0x3b67ad['OXIIi'](_0x3b67ad["RaTud"] + _0x42eb74 + _0x3b67ad["aqQTo"], _0x3b67ad["bMvCo"](md5, _0x3b67ad["OXIIi"](_0x42eb74, 'token_20230313000136kwyktxb0tgspm00yo5'), 16)) + '\x22}');
```

通过对各个函数分别打印输出，发现：

- `_0x3b67ad["bMvCo"]` 就是生成 Token 的关键函数
- `_0x3b67ad["OXIIi"]` 是字符串拼接函数
- `_0x42eb74` 就是页面中提取到的 ID

继续追踪 `bMvCo` 函数的定义：

```javascript
'bMvCo': function(_0x2b8bab, _0x2a17ff, _0x37f715) {
    return _0x2b8bab(_0x2a17ff, _0x37f715);
},

// 还原后：
'bMvCo': function(md5, id + 固定token, 16) {
    return md5(id + 固定token, 16);
},
```

这个函数内部就是调用了 MD5 加密函数。

## Token 生成机制

整个 Token 的生成逻辑如下：

1. 从 HTML 页面中提取动态生成的 ID
2. 从 JS 脚本中找到固定字符串 `token_20230313000136kwyktxb0tgspm00yo5`
3. 将 ID 与固定 Token 进行拼接
4. 对拼接后的字符串进行 MD5 加密（取 16 位）
5. 将加密结果作为 Token 发送给服务器

```
ID + 固定Token  →  MD5(16位)  →  Token
```

## 参数

分析过程中还有一个问题：用户输入的域名参数是在哪里发送的？

查看网络请求记录，并没有发现单独的域名发送请求。进一步检查 HTML 表单，发现域名就藏在表单里面。

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 192616.png" alt="HTML 表单中的域名参数">

所以在实现爬虫或 API 时，只需要构造正确的 POST 请求，把表单数据发送出去即可。

## 总结

这次分析下来，itdog 的 Token 机制并不算复杂：固定 Token 配合动态 ID，再加上一层 MD5 加密。如果要自己写一个调用工具，只需要：

1. 请求页面获取 ID
2. 拼接 ID 与固定 Token
3. MD5 加密生成 Token
4. 通过 WebSocket 建立连接并发送数据

<img src="https://raw.githubusercontent.com/Domdkw/warehouse/191f385d0ded3ea32c393359c8e6998d24c215a2/gist/26.4.11/屏幕截图 2026-04-11 201439.png" alt="WebSocket 返回内容">

WebSocket 返回的内容包含省份、地区、响应时间等信息，稍作处理就能得到完整的检测结果。
