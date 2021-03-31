# binary ninja使用的一些记录

## 内置的python如何调用外部python的库(Personal License)

1. 目前binary ninja的版本是2.3.2660，内置的python是3.8.3，
可以本地安装一个同版本的python，因为高版本的python装的库他
调用会失败，所以最好同版本。
2. 在binary ninja的插件里面先`import sys`然后`sys.append('/path/to/python/site-packages')`

## 一些遇见的小问题

### 1. 获取当前指令的arch

>一般情况下通过传递给插件的BinaryView参数是可以获取到准确的arch的，
>但是分析arm的库的时候，他arch会一直返回arm，这个时候如果是thumb指令用他去assemble
>之后再去patch就会出错，正确的方式是调用当前
>MediumLevelILInstruction的`.function.arch`去获取正确的arch，
>然后去assemble就不会出错了