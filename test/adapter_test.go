// Package test 提供 gf-casbin-adapter 的集成测试
package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gogf/gf/v2/database/gdb"
	adapter "github.com/hailaz/gf-casbin-adapter/v2"

	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	// _ "github.com/gogf/gf/contrib/drivers/clickhouse/v2"
	// _ "github.com/gogf/gf/contrib/drivers/mssql/v2"
	// _ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	// _ "github.com/gogf/gf/contrib/drivers/oracle/v2"
)

// HTTP 方法常量定义
const (
	ACTION_GET    = "(GET)"                                                // GET 请求方法
	ACTION_POST   = "(POST)"                                               // POST 请求方法
	ACTION_PUT    = "(PUT)"                                                // PUT 请求方法
	ACTION_DELETE = "(DELETE)"                                             // DELETE 请求方法
	ACTION_ALL    = "(GET)|(POST)|(PUT)|(DELETE)|(PATCH)|(OPTIONS)|(HEAD)" // 所有 HTTP 方法
	ADMIN_NAME    = "admin"                                                // 超级管理员用户名
	NORMAL_NAME   = "hailaz"                                               // 普通用户用户名
)

// testCase 定义测试用例结构
type testCase struct {
	name     string // 测试用例名称
	user     string // 测试用户
	path     string // 测试路径
	method   string // 请求方法
	expected bool   // 预期结果
}

// adapterConfig 定义适配器配置结构
type adapterConfig struct {
	runTest   bool           // 是否运行测试
	name      string         // 数据库类型名称
	config    gdb.ConfigNode // 数据库配置
	initSQL   string         // 初始化 SQL
	modelPath string         // Casbin 模型配置路径
	tableName string         // 自定义表名
}

// getTestDBConfigs 返回测试数据库配置列表
func getTestDBConfigs() []adapterConfig {
	return []adapterConfig{
		{
			runTest: true,
			name:    "sqlite",
			config: gdb.ConfigNode{
				Type:  "sqlite",
				Link:  "sqlite::@file(casbin.db)",
				Debug: true,
			},
			tableName: "casbin_rule_test",
			initSQL: `CREATE TABLE IF NOT EXISTS casbin_rule_test (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ptype VARCHAR(255) NOT NULL DEFAULT '',
				v0 VARCHAR(255) NOT NULL DEFAULT '',
				v1 VARCHAR(255) NOT NULL DEFAULT '',
				v2 VARCHAR(255) NOT NULL DEFAULT '',
				v3 VARCHAR(255) NOT NULL DEFAULT '',
				v4 VARCHAR(255) NOT NULL DEFAULT '',
				v5 VARCHAR(255) NOT NULL DEFAULT ''
			)`,
			modelPath: "conf/rbac.conf",
		},
		{
			runTest: true,
			name:    "mysql",
			config: gdb.ConfigNode{
				Type:  "mysql",
				Link:  "test:123456@tcp(localhost:3306)/casbin",
				Debug: true,
			},
			tableName: "casbin_rule_test",
			initSQL: `CREATE TABLE IF NOT EXISTS casbin_rule_test (
				id int(11) NOT NULL AUTO_INCREMENT,
				ptype varchar(255) NOT NULL DEFAULT '',
				v0 varchar(255) NOT NULL DEFAULT '',
				v1 varchar(255) NOT NULL DEFAULT '',
				v2 varchar(255) NOT NULL DEFAULT '',
				v3 varchar(255) NOT NULL DEFAULT '',
				v4 varchar(255) NOT NULL DEFAULT '',
				v5 varchar(255) NOT NULL DEFAULT '',
				PRIMARY KEY (id)
			) ENGINE=InnoDB`,
			modelPath: "conf/rbac.conf",
		},
	}
}

// TestObj 封装测试对象
type TestObj struct {
	t        *testing.T       // 测试实例
	enforcer *casbin.Enforcer // Casbin 执行器
}

// initCasbinEnforcer 初始化 Casbin 执行器
// 参数:
//   - conf: 适配器配置
//
// 返回:
//   - *casbin.Enforcer: Casbin 执行器实例
//   - error: 错误信息
func initCasbinEnforcer(conf adapterConfig) (*casbin.Enforcer, error) {
	myDB, err := gdb.New(conf.config)
	if err != nil {
		return nil, fmt.Errorf("init db failed: %v", err)
	}

	if conf.initSQL != "" {
		if _, err = myDB.Exec(context.TODO(), conf.initSQL); err != nil {
			return nil, fmt.Errorf("init table failed: %v", err)
		}
	}

	a := adapter.NewAdapter(adapter.Options{
		GDB:       myDB,
		TableName: conf.tableName,
	})
	e, err := casbin.NewEnforcer(conf.modelPath, a)
	if err != nil {
		return nil, fmt.Errorf("new enforcer failed: %v", err)
	}

	if err = e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load policy failed: %v", err)
	}

	return e, nil
}

// SetupTestData 设置测试数据
// 参数:
//   - rules: 权限规则列表
func (o *TestObj) SetupTestData(rules [][]string) {
	// 清理已有策略
	o.enforcer.DeletePermissionForUser(ADMIN_NAME)
	o.enforcer.DeletePermissionForUser(NORMAL_NAME)

	if exist, err := o.enforcer.AddPolicies(rules); err != nil {
		o.t.Fatalf("add policies failed: %v", err)
	} else {
		o.t.Log("add policies success:", exist)
	}
}

// Test_CasbinPolicy 测试 Casbin 权限策略
// 测试内容：
// 1. 管理员权限验证
// 2. 普通用户权限验证
// 3. 非法访问验证
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
			enforcer, err := initCasbinEnforcer(dbConf)
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

// Test_UpdatePolicy 测试更新策略功能
func Test_UpdatePolicy(t *testing.T) {
	rules := [][]string{
		{ADMIN_NAME, "*", ACTION_ALL},
		{NORMAL_NAME, "/api/v1/*", ACTION_GET},
	}

	for _, dbConf := range getTestDBConfigs() {
		if !dbConf.runTest {
			continue
		}
		t.Run(dbConf.name, func(t *testing.T) {
			enforcer, err := initCasbinEnforcer(dbConf)
			if err != nil {
				t.Fatalf("init db failed: %v", err)
			}

			obj := TestObj{t: t, enforcer: enforcer}
			obj.SetupTestData(rules)

			// 测试更新策略
			oldRule := []string{NORMAL_NAME, "/api/v1/*", ACTION_GET}
			newRule := []string{NORMAL_NAME, "/api/v2/*", ACTION_GET}

			success, err := enforcer.UpdatePolicy(oldRule, newRule)
			if err != nil {
				t.Errorf("update policy failed: %v", err)
			}
			if !success {
				t.Error("update policy failed")
			}

			// 验证更新后的权限
			testCases := []testCase{
				{
					name:     "test old path after update",
					user:     NORMAL_NAME,
					path:     "/api/v1/user/list",
					method:   ACTION_GET,
					expected: false,
				},
				{
					name:     "test new path after update",
					user:     NORMAL_NAME,
					path:     "/api/v2/user/list",
					method:   ACTION_GET,
					expected: true,
				},
			}

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

// Test_RemovePolicy 测试删除策略功能
func Test_RemovePolicy(t *testing.T) {
	rules := [][]string{
		{ADMIN_NAME, "*", ACTION_ALL},
		{NORMAL_NAME, "/api/v1/*", ACTION_GET},
	}

	for _, dbConf := range getTestDBConfigs() {
		if !dbConf.runTest {
			continue
		}
		t.Run(dbConf.name, func(t *testing.T) {
			enforcer, err := initCasbinEnforcer(dbConf)
			if err != nil {
				t.Fatalf("init db failed: %v", err)
			}

			obj := TestObj{t: t, enforcer: enforcer}
			obj.SetupTestData(rules)

			// 删除策略
			success, err := enforcer.RemovePolicy(NORMAL_NAME, "/api/v1/*", ACTION_GET)
			if err != nil {
				t.Errorf("remove policy failed: %v", err)
			}
			if !success {
				t.Error("remove policy failed")
			}

			// 验证删除后的权限
			ok, err := enforcer.Enforce(NORMAL_NAME, "/api/v1/user/list", ACTION_GET)
			if err != nil {
				t.Errorf("enforce failed: %v", err)
			}
			if ok {
				t.Error("policy should be removed")
			}
		})
	}
}
