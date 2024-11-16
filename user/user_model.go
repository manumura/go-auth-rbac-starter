package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/role"
)

// TODO AuthenticatedUserModel
// export class AuthenticatedUserModel {
// 	@Expose()
// 	@ApiProperty()
// 	public readonly uuid: UUID;

// 	@Expose()
// 	@ApiProperty()
// 	public name: string;

// 	@Expose()
// 	@ApiProperty()
// 	public isActive: boolean;

// 	@Expose()
// 	@ApiProperty()
// 	public imageId: string;

// 	@Expose()
// 	@ApiProperty()
// 	public imageUrl: string;

// 	@Expose()
// 	@ApiProperty({ enum: Role })
// 	public role: Role;

// 	@Expose()
// 	@ApiProperty()
// 	public createdAt: Date;

//		@Expose()
//		@ApiProperty()
//		public updatedAt: Date;
//	  }
type User struct {
	ID              int64      `json:"id"`
	Uuid            uuid.UUID  `json:"uuid"`
	Name            string     `json:"name"`
	IsActive        bool       `json:"isActive"`
	ImageID         string     `json:"imageId"`
	ImageUrl        string     `json:"imageUrl"`
	Role            role.Role  `json:"role"`
	CreatedAt       *time.Time `json:"createdAt"`
	UpdatedAt       *time.Time `json:"updatedAt"`
	Password        string     `json:"password"`
	Email           string     `json:"email"`
	IsEmailVerified bool       `json:"isEmailVerified"`
}

type AuthenticatedUser struct {
	Uuid      uuid.UUID  `json:"uuid"`
	Name      string     `json:"name"`
	IsActive  bool       `json:"isActive"`
	ImageID   string     `json:"imageId"`
	ImageUrl  string     `json:"imageUrl"`
	Role      role.Role  `json:"role"`
	CreatedAt *time.Time `json:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt"`
}

type CreateUserRequest struct {
	Name     string    `json:"name" validate:"required,min=6,max=100"`
	Email    string    `json:"email" validate:"required,email"`
	Password string    `json:"password" validate:"required"`
	Role     role.Role `json:"role" validate:"required,alpha"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=6,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
