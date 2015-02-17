# http_stat 简介
http_stat 是一个linux module, 在POST_ROUTING,LOCAL_IN处对经过的http内容做检查和替换，放置在服务器，本地，或者网关位置都可以工作。用来匹配responses中的特定编号,然后替换内容,比如替换所有404页面的内容，如下图：

![Alt text][http_img1]


### 使用
```
#在linux-3.2.62上测试通过，make前请确认有module编译环境
git clone https://github.com/yubo/http_stat.git
cd http_stat
make
make start
```


### 配置
请阅读

* Makefile
* conf/404.html

[http_img1]: https://raw.github.com/yubo/http_stat/master/doc/http_stat.jpg
