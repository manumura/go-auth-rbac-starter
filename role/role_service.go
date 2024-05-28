package role

import (
	"context"

	"github.com/manumura/go-auth-rbac-starter/db"
)

type RoleService interface {
	InitRolesMaps(ctx context.Context)
}

type RoleServiceImpl struct {
	datastore db.DataStore
}

func NewRoleService(datastore db.DataStore) RoleService {
	return &RoleServiceImpl{
		datastore: datastore,
	}
}

var RoleNameToID = map[string]int64{}
var RoleIDToName = map[int64]string{}

func (service *RoleServiceImpl) InitRolesMaps(ctx context.Context) {
	r, err := service.datastore.GetRoles(ctx)
	if err != nil {
		return
	}

	for _, role := range r {
		RoleNameToID[role.Name] = role.ID
		RoleIDToName[role.ID] = role.Name
	}
}
