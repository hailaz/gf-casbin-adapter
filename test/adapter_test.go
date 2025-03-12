package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gogf/gf/v2/database/gdb"
	adapter "github.com/hailaz/gf-casbin-adapter/v2"

	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	// _ "github.com/gogf/gf/contrib/drivers/clickhouse/v2"
	// _ "github.com/gogf/gf/contrib/drivers/mssql/v2"
	// _ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	// _ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	// _ "github.com/gogf/gf/contrib/drivers/oracle/v2"
)

const (
	ACTION_GET    = "(GET)"
	ACTION_POST   = "(POST)"
	ACTION_PUT    = "(PUT)"
	ACTION_DELETE = "(DELETE)"
	ACTION_ALL    = "(GET)|(POST)|(PUT)|(DELETE)|(PATCH)|(OPTIONS)|(HEAD)"
	ADMIN_NAME    = "admin"  //超级管理员用户名
	NORMAL_NAME   = "hailaz" //普通用户用户名
)

type testCase struct {
	name     string
	user     string
	path     string
	method   string
	expected bool
}

type dbConfig struct {
	runTest bool
	name    string
	config  gdb.ConfigNode
	initSQL string
}

func getTestDBConfigs() []dbConfig {
	return []dbConfig{
		{
			runTest: true,
			name:    "sqlite",
			config: gdb.ConfigNode{
				Type:  "sqlite",
				Link:  "sqlite::@file(casbin.db)",
				Debug: true,
			},
			initSQL: `CREATE TABLE IF NOT EXISTS casbin_rule (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ptype VARCHAR(255) NOT NULL DEFAULT '',
				v0 VARCHAR(255) NOT NULL DEFAULT '',
				v1 VARCHAR(255) NOT NULL DEFAULT '',
				v2 VARCHAR(255) NOT NULL DEFAULT '',
				v3 VARCHAR(255) NOT NULL DEFAULT '',
				v4 VARCHAR(255) NOT NULL DEFAULT '',
				v5 VARCHAR(255) NOT NULL DEFAULT ''
			)`,
		},
		// 可以添加其他数据库配置
	}
}

// TestObj description
type TestObj struct {
	t        *testing.T
	enforcer *casbin.Enforcer
}

func initDB(conf dbConfig) (*casbin.Enforcer, error) {
	myDB, err := gdb.New(conf.config)
	if err != nil {
		return nil, fmt.Errorf("init db failed: %v", err)
	}

	if conf.initSQL != "" {
		if _, err = myDB.Exec(context.TODO(), conf.initSQL); err != nil {
			return nil, fmt.Errorf("init table failed: %v", err)
		}
	}

	a := adapter.NewAdapter(adapter.Options{GDB: myDB})
	e, err := casbin.NewEnforcer("rbac.conf", a)
	if err != nil {
		return nil, fmt.Errorf("new enforcer failed: %v", err)
	}

	if err = e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load policy failed: %v", err)
	}

	return e, nil
}

func (o *TestObj) SetupTestData(rules [][]string) {
	// 清理已有策略
	// enforcer.ClearPolicy()
	o.enforcer.DeletePermissionForUser(ADMIN_NAME)
	o.enforcer.DeletePermissionForUser(NORMAL_NAME)

	if _, err := o.enforcer.AddPolicies(rules); err != nil {
		o.t.Fatalf("add policies failed: %v", err)
	}
}

func Test_CasbinPolicy(t *testing.T) {
	rules := [][]string{
		// 设置管理员权限
		{ADMIN_NAME, "*", ACTION_ALL},
		// 设置普通用户权限
		{NORMAL_NAME, "/api/v1/*", ACTION_GET},
		{NORMAL_NAME, "/api/v2/user/list", ACTION_GET},
		{NORMAL_NAME, "/api/v2/user/add", ACTION_POST},
	}
	testCases := []testCase{
		{
			name:     "admin with root access",
			user:     ADMIN_NAME,
			path:     "/",
			method:   ACTION_GET,
			expected: true,
		},
		{
			name:     "normal user with api access",
			user:     NORMAL_NAME,
			path:     "/api/v1/user/list",
			method:   ACTION_GET,
			expected: true,
		},
		{
			name:     "normal user with wrong method",
			user:     NORMAL_NAME,
			path:     "/api/v1/user/list",
			method:   ACTION_POST,
			expected: false,
		},
	}

	for _, dbConf := range getTestDBConfigs() {
		if !dbConf.runTest {
			continue
		}
		t.Run(dbConf.name, func(t *testing.T) {
			enforcer, err := initDB(dbConf)
			if err != nil {
				t.Fatalf("init db failed: %v", err)
			}

			obj := TestObj{t: t, enforcer: enforcer}
			obj.SetupTestData(rules)

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ok, err := enforcer.Enforce(tc.user, tc.path, tc.method)
					if err != nil {
						t.Errorf("enforce failed: %v", err)
					}
					if ok != tc.expected {
						t.Errorf("expected %v but got %v", tc.expected, ok)
					}
				})
			}
		})
	}
}
