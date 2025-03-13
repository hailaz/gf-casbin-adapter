package adapter

import (
	"context"
	"fmt"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// UpdatePolicy updates policy rule from all instance.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	return a.o.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		_, err := tx.Model(a.tableName).Safe().Ctx(ctx).Where(a.toData(ptype, oldRule)).Data(a.toData(ptype, newRule)).Update()
		return err
	})
}

// UpdatePolicies updates some policy rules from all instance
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return fmt.Errorf("oldRules and newRules length not match")
	}

	return a.o.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for i := range oldRules {
			_, err := tx.Model(a.tableName).Safe().Ctx(ctx).Where(a.toData(ptype, oldRules[i])).Data(a.toData(ptype, newRules[i])).Update()
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// 查询需要更新的旧规则
	qs := a.o.Model(a.tableName).Safe().Ctx(a.ctx)
	qs = qs.Where(a.fieldName.PType, ptype)

	for index := 0; index <= CASBIN_V_LEN-1; index++ {
		if fieldIndex <= index && index < fieldIndex+len(fieldValues) {
			qs = qs.Where(a.fieldName.V[index], fieldValues[index-fieldIndex])
		}
	}

	// 获取旧规则
	oldRes, err := qs.All()
	if err != nil {
		return nil, err
	}

	// 构建旧规则数组
	var oldRules [][]string
	for _, line := range oldRes {
		rule := make([]string, 0, a.fieldName.VLen)
		for i := 0; i < a.fieldName.VLen; i++ {
			rule = append(rule, line[a.fieldName.V[i]].String())
		}
		oldRules = append(oldRules, rule)
	}

	// 在事务中执行删除旧规则和添加新规则
	err = a.o.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// 删除旧规则
		_, err := qs.Delete()
		if err != nil {
			return err
		}

		// 添加新规则
		if len(newRules) > 0 {
			var lines g.List
			for _, rule := range newRules {
				line := a.toData(ptype, rule)
				lines = append(lines, line)
			}
			_, err = tx.Model(a.tableName).Ctx(ctx).Data(lines).Insert()
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return oldRules, nil
}
