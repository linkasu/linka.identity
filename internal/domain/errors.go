package domain

import "errors"

var (
	ErrInvalid   = errors.New("invalid input")
	ErrForbidden = errors.New("operation is forbidden")
	ErrNotFound  = errors.New("resource not found")
	ErrConflict  = errors.New("resource conflict")
)
