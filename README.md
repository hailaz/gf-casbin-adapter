# gf-casbin-adapter

## 如何使用

1. 创建数据库表

```sql
DROP TABLE IF EXISTS `casbin_rule`;
CREATE TABLE `casbin_rule` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ptype` varchar(255) NOT NULL DEFAULT '',
  `v0` varchar(255) NOT NULL DEFAULT '',
  `v1` varchar(255) NOT NULL DEFAULT '',
  `v2` varchar(255) NOT NULL DEFAULT '',
  `v3` varchar(255) NOT NULL DEFAULT '',
  `v4` varchar(255) NOT NULL DEFAULT '',
  `v5` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB;
```

2. 使用

具体看 [adapter_test.go](test/adapter_test.go)

> 特别注意：默认的`p_type`字段名改为`ptype`，如需要使用`p_type`参考如下代码
> ```
> adapter.NewAdapter(
> 		adapter.Options{
> 			GDB:       myDB,
> 			FieldName: adapter.FieldName{PType: "p_type"},
> 		})
> ```


## For GoFrame v2

```go
go get github.com/hailaz/gf-casbin-adapter/v2
```

## For GoFrame v1

```go
go get github.com/hailaz/gf-casbin-adapter
```