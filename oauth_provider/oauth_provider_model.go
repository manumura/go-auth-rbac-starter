package oauthprovider

type OauthProvider string

const (
	GOOGLE   OauthProvider = "GOOGLE"
	FACEBOOK OauthProvider = "FACEBOOK"
)

func (p OauthProvider) String() string {
	return string(p)
}
