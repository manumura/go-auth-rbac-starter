package profile

type UpdateProfileRequest struct {
	Name string `json:"name" validate:"required,max=100"`
}

type UpdatePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required,min=8"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}
