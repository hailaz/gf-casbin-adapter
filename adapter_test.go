package adapter_test

import (
	"net/http"
	"testing"

	"github.com/casbin/casbin/v2"
	_ "github.com/gogf/gf/contrib/drivers/clickhouse/v2"
	_ "github.com/gogf/gf/contrib/drivers/mssql/v2"
	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"

	// _ "github.com/gogf/gf/contrib/drivers/oracle/v2"
	"github.com/gogf/gf/v2/database/gdb"
	adapter "github.com/hailaz/gf-casbin-adapter/v2"
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
	var err error
	myDB, err = gdb.New(gdb.ConfigNode{
		Type: "mysql",
		Link: "test:123456@tcp(localhost:3306)/mydb",
	})
	if err != nil {
		panic(err)
	}
	a := adapter.NewAdapter(adapter.Options{GDB: myDB})
	Enforcer, err = casbin.NewEnforcer("./test/rbac.conf", a)
	if err != nil {
		panic(err)
	}
	err = Enforcer.LoadPolicy()
	if err != nil {
		panic(err)
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

	ok, err := Enforcer.DeletePermissionsForUser(user)
	if err != nil {
		t.Error(err)
	}
	t.Logf("delete user premission:%v", ok)
	CheckPremission(t, user, path, method)
	AddPremission(t, user, "*", ACTION_ALL)
	CheckPremission(t, user, path, method)

	user1 := "hailaz"
	path1 := "/api/v1/*"
	checkPathTrue := "/api/v1/user/list"
	checkPathFalse := "/api/v2/user/list"
	AddPremission(t, user1, path1, ACTION_GET)
	CheckPremission(t, user1, checkPathTrue, ACTION_POST)
	CheckPremission(t, user1, checkPathFalse, http.MethodGet)
	CheckPremission(t, user1, checkPathTrue, http.MethodGet)
}

// CheckPremission description
//
// createTime: 2022-07-01 11:34:19
//
// author: hailaz
func CheckPremission(t *testing.T, user string, path string, method string) {
	ok, err := Enforcer.Enforce(user, path, method)
	if err != nil {
		t.Error(err)
	}
	t.Logf("check \tuser[%s] \tpremission[%s] \tpath[%s] \tallow[%v]", user, method, path, ok)
}

// Add description
//
// createTime: 2022-07-01 12:19:16
//
// author: hailaz
func AddPremission(t *testing.T, user string, path string, method string) {
	ok, err := Enforcer.AddPolicy(user, path, method)
	if err != nil {
		t.Error(err)
	}
	t.Logf("add \tuser[%s] \tpremission[%s] \tpath[%s] \tresult[%v]", user, method, path, ok)
}
