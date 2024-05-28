package role

type Role string

const (
	ADMIN Role = "ADMIN"
	USER  Role = "USER"
)

func (r Role) String() string {
	return string(r)
}
