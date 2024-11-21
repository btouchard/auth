package models

import (
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/storage"
	"time"
)

type Actor interface {
	GetID() uuid.UUID
	GetAud() string
	GetIdentifier() string
	GetRole() string
	IsFromSSO() bool
	SetLastSignInAt(time.Time)
	UpdateLastSignInAt(tx *storage.Connection) error
}
