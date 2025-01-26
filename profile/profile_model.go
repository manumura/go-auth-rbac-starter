package profile

type UpdateProfileRequest struct {
	Name string `json:"name" validate:"required,max=100"`
}

type UpdateProfileParams struct {
	Name string `json:"name" validate:"required,max=100"`
}

type UpdatePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required,min=8"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

type UpdatePasswordParams struct {
	OldPassword string `json:"oldPassword" validate:"required,min=8"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

type UpdateImageParams struct {
	ImageID  string `json:"imageId" validate:"required"`
	ImageURL string `json:"imageUrl" validate:"required,url"`
}
