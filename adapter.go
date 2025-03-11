package adapter

import (
	"context"
	"runtime"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
)

type CasbinRule struct {
	Id    int64
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// FieldName 字段名
type FieldName struct {
	Id    string
	PType string
	V     []string
}

const (
	CASBINRULE_TABLE_NAME = "casbin_rule"
	CASBIN_V_LEN          = 6
)

var (
	// 判断是否实现了persist.*接口
	_ persist.Adapter      = new(Adapter)
	_ persist.BatchAdapter = new(Adapter)

	DefaultFieldName = FieldName{
		Id:    "id",
		PType: "ptype",
		V:     []string{"v0", "v1", "v2", "v3", "v4", "v5"},
	}
)

// Options 输入配置
type Options struct {
	Ctx       context.Context
	GDB       gdb.DB // gdb
	TableName string // 表名
	FieldName FieldName
}

// Adapter represents the Xorm adapter for policy storage.
type Adapter struct {
	ctx       context.Context
	o         gdb.DB
	tableName string
	fieldName *FieldName
}

func NewAdapter(opts Options) *Adapter {
	fieldName := DefaultFieldName

	a := &Adapter{
		o:         opts.GDB,
		tableName: CASBINRULE_TABLE_NAME,
		fieldName: &fieldName,
	}

	if opts.Ctx != nil {
		a.ctx = opts.Ctx
	} else {
		a.ctx = gctx.New()
	}

	if opts.TableName != "" {
		a.tableName = opts.TableName
	}

	a.SetFieldName(opts.FieldName)

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

// NewAdapterWithTableName 设置表名
//
// createTime: 2022-03-04 17:04:32
//
// author: hailaz
func NewAdapterWithTableName(gdb gdb.DB, tableName string) *Adapter {
	return NewAdapter(Options{GDB: gdb, TableName: tableName})
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
}

func (a *Adapter) SetFieldName(fieldName FieldName) {
	if fieldName.Id != "" {
		a.fieldName.Id = fieldName.Id
	}
	if fieldName.PType != "" {
		a.fieldName.PType = fieldName.PType
	}
	if len(fieldName.V) >= 5 {
		a.fieldName.V = fieldName.V
	}
}

func (a *Adapter) open() {

}

// close 关闭
func (a *Adapter) close() {
	a.o.Close(a.ctx)
	a.o = nil
}

// createTable 不支持
func (a *Adapter) createTable() {
}

// dropTable 不支持
func (a *Adapter) dropTable() {
}

func loadPolicyLine(line CasbinRule, model model.Model) {

	lineText := strings.Join([]string{
		line.PType,
		line.V0,
		line.V1,
		line.V2,
		line.V3,
		line.V4,
		line.V5,
	}, ",")
	lineText = strings.TrimRight(lineText, ",")

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []CasbinRule
	err := a.o.Model(a.tableName).Scan(&lines)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// toData description
func (a *Adapter) toData(ptype string, rule []string) g.Map {
	data := g.Map{
		a.fieldName.PType: ptype,
	}

	for index := 0; index < len(rule); index++ {
		data[a.fieldName.V[index]] = rule[index]
	}

	return data
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	var lines []CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	_, err := a.o.Ctx(a.ctx).Model(a.tableName).FieldsEx(a.fieldName.Id).Data(lines).Insert()
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.o.Ctx(a.ctx).Model(a.tableName).FieldsEx(a.fieldName.Id).Insert(line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	qs := a.o.Model(a.tableName).Safe()
	qs = qs.Where(a.fieldName.PType, ptype)
	for index := 0; index < len(rule); index++ {
		qs = qs.Where(a.fieldName.V[index], rule[index])
	}
	_, err := qs.Delete()
	return err

}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	qs := a.o.Model(a.tableName).Safe()
	qs = qs.Where(a.fieldName.PType, ptype)
	for index := 0; index <= CASBIN_V_LEN-1; index++ {
		if fieldIndex <= index && index < fieldIndex+len(fieldValues) {
			qs = qs.Where(a.fieldName.V[index], fieldValues[index-fieldIndex])
		}
	}
	_, err := qs.Delete()
	return err
}

func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	_, err := a.o.Ctx(a.ctx).Model(a.tableName).FieldsEx(a.fieldName.Id).Data(lines).Insert()
	return err
}

func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(a.ctx, sec, ptype, rules)
}

// RemovePoliciesCtx removes multiple policy rules from the storage.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return a.o.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		for _, rule := range rules {
			_, err := tx.Model(a.tableName).Safe().Ctx(ctx).Where(a.toData(ptype, rule)).Delete()
			if err != nil {
				return err
			}
		}
		return nil
	})
}
