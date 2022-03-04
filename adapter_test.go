package adapter_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/casbin/casbin"
	"github.com/gogf/gf/database/gdb"
	adapter "github.com/hailaz/gf-casbin-adapter"
)

const (
	ACTION_GET    = "(GET)"
	ACTION_POST   = "(POST)"
	ACTION_PUT    = "(PUT)"
	ACTION_DELETE = "(DELETE)"
	ACTION_ALL    = "(GET)|(POST)|(PUT)|(DELETE)|(PATCH)|(OPTIONS)|(HEAD)"
	ADMIN_NAME    = "admin" //超级管理员用户名
)

var myDB gdb.DB
var Enforcer *casbin.Enforcer

// init description
//
// createTime: 2022-03-04 17:14:35
//
// author: hailaz
func init() {
	gdb.SetConfig(gdb.Config{
		"default": gdb.ConfigGroup{
			gdb.ConfigNode{
				Type: "mysql",
				Link: "test:123456@tcp(localhost:3306)/mydb",
			},
		},
	})
	var err error
	myDB, err = gdb.New()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	a := adapter.NewAdapter(adapter.Options{GDB: myDB})
	Enforcer = casbin.NewEnforcer("./test/rbac.conf", a)
	err = Enforcer.LoadPolicy()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

// Test_New description
//
// createTime: 2022-03-04 17:13:35
//
// author: hailaz
func Test_New(t *testing.T) {
	user := ADMIN_NAME
	path := "/"
	method := http.MethodGet
	t.Logf("\nuser:%v\npath:%v\nmethod:%v", user, path, method)
	t.Logf("delete user premission:%v", Enforcer.DeletePermissionsForUser(user))
	t.Logf("check user premission:%v", Enforcer.Enforce(user, path, method))
	t.Logf("add user premission:%v", Enforcer.AddPolicy(user, "*", ACTION_ALL))
	t.Logf("check user premission again:%v", Enforcer.Enforce(user, path, method))
}
