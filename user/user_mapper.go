package user

func ToUserResponse(user User) UserResponse {
	return UserResponse{
		Uuid:      user.Uuid,
		Name:      user.Name,
		Email:     user.Email,
		IsActive:  user.IsActive,
		ImageId:   user.ImageId,
		ImageUrl:  user.ImageUrl,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}
