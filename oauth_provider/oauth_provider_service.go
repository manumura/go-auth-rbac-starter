package oauthprovider

import (
	"context"

	"github.com/manumura/go-auth-rbac-starter/db"
)

type OauthProviderService interface {
	InitProvidersMaps(ctx context.Context)
}

type OauthProviderServiceImpl struct {
	datastore db.DataStore
}

func NewOauthProviderService(datastore db.DataStore) OauthProviderService {
	return &OauthProviderServiceImpl{
		datastore: datastore,
	}
}

var OauthProviderNameToID = map[string]int64{}
var OauthProviderIDToName = map[int64]string{}

func (service *OauthProviderServiceImpl) InitProvidersMaps(ctx context.Context) {
	p, err := service.datastore.GetOauthProviders(ctx)
	if err != nil {
		return
	}

	for _, provider := range p {
		OauthProviderNameToID[provider.Name] = provider.ID
		OauthProviderIDToName[provider.ID] = provider.Name
	}
}
