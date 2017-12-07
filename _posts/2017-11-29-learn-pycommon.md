---
title: "python基础知识备忘"
author_profile: ture
publish: NO
toc: true
toc_label: "目录"
categories:
  - 自学系列
tags:
  - python
---

## Iterable
python中，只要是`collections.Iterable`类型的对象，均为可迭代对象

```python
"""判断是否是Iterable对象"""
from collections import Iterable
isinstance('kdkd', Iterable) #字符串也是
isinstance((1,2,3,4), Iterable) #turple也是一种
isinstance({'key1':1, 'key2':2}, Iterable)

```

可迭代对象均可施以下列操作：

```python

# dic默认情况下遍历的是key
>>> for k in {'k1':1, 'k2':2}:
...     print k
... 
k2
k1

# dic默认情况下遍历的是key，若要value和key，需要使用iteritems方法
>>> for k, v in {'k1':1, 'k2':2}.iteritems():
...     print (k, v)
... 
('k2', 2)
('k1', 1)

```

