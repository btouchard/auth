package models

import (
	"database/sql"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
	"time"
)

type Actor interface {
	GetID() uuid.UUID
	GetAud() string
	GetIdentifier() string
	GetRole() string
	IsFromSSO() bool
	IsBanned() bool
	SetLastSignInAt(time.Time)
	UpdateLastSignInAt(tx *storage.Connection) error
}

// FindActorWithRefreshToken finds a user from the provided refresh token. If
// forUpdate is set to true, then the SELECT statement used by the query has
// the form SELECT ... FOR UPDATE SKIP LOCKED. This means that a FOR UPDATE
// lock will only be acquired if there's no other lock. In case there is a
// lock, a IsNotFound(err) error will be returned.
func FindActorWithRefreshToken(tx *storage.Connection, token string, forUpdate bool) (Actor, *RefreshToken, *Session, error) {
	refreshToken := &RefreshToken{}

	if forUpdate {
		// pop does not provide us with a way to execute FOR UPDATE
		// queries which lock the rows affected by the query from
		// being accessed by any other transaction that also uses FOR
		// UPDATE
		if err := tx.RawQuery(fmt.Sprintf("SELECT * FROM %q WHERE token = ? LIMIT 1 FOR UPDATE SKIP LOCKED;", refreshToken.TableName()), token).First(refreshToken); err != nil {
			if errors.Cause(err) == sql.ErrNoRows {
				return nil, nil, nil, RefreshTokenNotFoundError{}
			}

			return nil, nil, nil, errors.Wrap(err, "error finding refresh token for update")
		}
	}

	// once the rows are locked (if forUpdate was true), we can query again using pop
	if err := tx.Where("token = ?", token).First(refreshToken); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil, nil, RefreshTokenNotFoundError{}
		}
		return nil, nil, nil, errors.Wrap(err, "error finding refresh token")
	}

	var actor Actor
	var err error
	if refreshToken.UserID != nil {
		actor, err = FindUserByID(tx, *refreshToken.UserID)
	} else if refreshToken.ClientID != nil {
		actor, err = FindClientByID(tx, *refreshToken.ClientID)
	}
	if err != nil {
		return nil, nil, nil, err
	}

	var session *Session

	if refreshToken.SessionId != nil {
		sessionId := *refreshToken.SessionId

		if sessionId != uuid.Nil {
			session, err = FindSessionByID(tx, sessionId, forUpdate)
			if err != nil {
				if forUpdate {
					return nil, nil, nil, err
				}

				if !IsNotFoundError(err) {
					return nil, nil, nil, errors.Wrap(err, "error finding session from refresh token")
				}

				// otherwise, there's no session for this refresh token
			}
		}
	}

	return actor, refreshToken, session, nil
}
