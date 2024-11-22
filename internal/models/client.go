package models

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// Client represents a registered client for auth
type Client struct {
	ID uuid.UUID `json:"id" db:"id"`

	Aud  string `json:"aud" db:"aud"`
	Role string `json:"role" db:"role"`

	ClientID        string     `json:"client_id" db:"client_id"`
	EncryptedSecret *string    `json:"-" db:"encrypted_secret"`
	LastSignInAt    *time.Time `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`
	BannedUntil     *time.Time `json:"banned_until,omitempty" db:"banned_until"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

func NewClientWithSecretHash(clientId, secretHash, aud string) (*Client, error) {
	if strings.HasPrefix(secretHash, crypto.Argon2Prefix) {
		_, err := crypto.ParseArgon2Hash(secretHash)
		if err != nil {
			return nil, err
		}
	} else if strings.HasPrefix(secretHash, crypto.FirebaseScryptPrefix) {
		_, err := crypto.ParseFirebaseScryptHash(secretHash)
		if err != nil {
			return nil, err
		}
	} else {
		// verify that the hash is a bcrypt hash
		_, err := bcrypt.Cost([]byte(secretHash))
		if err != nil {
			return nil, err
		}
	}
	id := uuid.Must(uuid.NewV4())
	client := &Client{
		ID:              id,
		Aud:             aud,
		ClientID:        clientId,
		EncryptedSecret: &secretHash,
	}
	return client, nil
}

// NewClient initializes a new user from an email, password and user data.
func NewClient(clientId, password, aud string) (*Client, error) {
	passwordHash := ""

	if password != "" {
		pw, err := crypto.GenerateFromPassword(context.Background(), password)
		if err != nil {
			return nil, err
		}

		passwordHash = pw
	}

	id := uuid.Must(uuid.NewV4())
	client := &Client{
		ID:              id,
		Aud:             aud,
		ClientID:        clientId,
		EncryptedSecret: &passwordHash,
	}
	return client, nil
}

// TableName overrides the table name used by pop
func (Client) TableName() string {
	return "clients"
}

func (c *Client) GetID() uuid.UUID {
	return c.ID
}

func (c *Client) GetAud() string {
	return c.Aud
}

func (c *Client) GetIdentifier() string {
	return c.ClientID
}

func (c *Client) GetRole() string {
	return c.Role
}

func (c *Client) IsFromSSO() bool {
	return false
}

func (c *Client) SetLastSignInAt(now time.Time) {
	c.LastSignInAt = &now
}

func (c *Client) HasPassword() bool {
	var pwd string

	if c.EncryptedSecret != nil {
		pwd = *c.EncryptedSecret
	}

	return pwd != ""
}

// SetRole sets the users Role to roleName
func (c *Client) SetRole(tx *storage.Connection, roleName string) error {
	c.Role = strings.TrimSpace(roleName)
	return tx.UpdateOnly(c, "role")
}

// HasRole returns true when the users role is set to roleName
func (c *Client) HasRole(roleName string) bool {
	return c.Role == roleName
}

// GetClientID returns the client client_id as a string
func (c *Client) GetClientID() string {
	return c.ClientID
}

// SetClientID sets the client client_id
func (c *Client) SetClientID(tx *storage.Connection, clientId string) error {
	c.ClientID = clientId
	return tx.UpdateOnly(c, "client_id")
}

// SetSecret update client secret
func (c *Client) SetSecret(ctx context.Context, secret string, encrypt bool, encryptionKeyID, encryptionKey string) error {
	if secret == "" {
		c.EncryptedSecret = nil
		return nil
	}

	pw, err := crypto.GenerateFromPassword(ctx, secret)
	if err != nil {
		return err
	}

	c.EncryptedSecret = &pw
	if encrypt {
		es, err := crypto.NewEncryptedString(c.ID.String(), []byte(pw), encryptionKeyID, encryptionKey)
		if err != nil {
			return err
		}

		encryptedPassword := es.String()
		c.EncryptedSecret = &encryptedPassword
	}

	return nil
}

// UpdateSecret updates the client's secret. Use UpdateSecret outside of a transaction first!
func (c *Client) UpdateSecret(tx *storage.Connection, sessionID *uuid.UUID) error {
	// These need to be reset because password change may mean the user no longer trusts the actions performed by the previous password.
	if err := tx.UpdateOnly(c, "encrypted_secret"); err != nil {
		return err
	}

	if err := ClearAllOneTimeTokensForUser(tx, c.ID); err != nil {
		return err
	}

	if sessionID == nil {
		// log out user from all sessions to ensure reauthentication after password change
		return Logout(tx, c.ID)
	} else {
		// log out user from all other sessions to ensure reauthentication after password change
		return LogoutAllExceptMe(tx, *sessionID, c.ID)
	}
}

// Authenticate a user from a password
func (c *Client) Authenticate(ctx context.Context, tx *storage.Connection, password string, decryptionKeys map[string]string, encrypt bool, encryptionKeyID string) (bool, bool, error) {
	if c.EncryptedSecret == nil {
		return false, false, nil
	}

	hash := *c.EncryptedSecret

	if hash == "" {
		return false, false, nil
	}

	es := crypto.ParseEncryptedString(hash)
	if es != nil {
		h, err := es.Decrypt(c.ID.String(), decryptionKeys)
		if err != nil {
			return false, false, err
		}

		hash = string(h)
	}

	compareErr := crypto.CompareHashAndPassword(ctx, hash, password)

	if !strings.HasPrefix(hash, crypto.Argon2Prefix) && !strings.HasPrefix(hash, crypto.FirebaseScryptPrefix) {
		// check if cost exceeds default cost or is too low
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			return compareErr == nil, false, err
		}

		if cost > bcrypt.DefaultCost || cost == bcrypt.MinCost {
			// don't bother with encrypting the password in Authenticate
			// since it's handled separately
			if err := c.SetSecret(ctx, password, false, "", ""); err != nil {
				return compareErr == nil, false, err
			}
		}
	}

	return compareErr == nil, encrypt && (es == nil || es.ShouldReEncrypt(encryptionKeyID)), nil
}

// UpdateLastSignInAt update field last_sign_in_at for user according to specified field
func (c *Client) UpdateLastSignInAt(tx *storage.Connection) error {
	return tx.UpdateOnly(c, "last_sign_in_at")
}

func findClient(tx *storage.Connection, query string, args ...interface{}) (*Client, error) {
	obj := &Client{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, ClientNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding client")
	}

	return obj, nil
}

// FindClientByClientIDAndAudience finds a user with the matching client_id and audience.
func FindClientByClientIDAndAudience(tx *storage.Connection, clientId, aud string) (*Client, error) {
	return findClient(tx, "client_id = ? and aud = ?", clientId, aud)
}

// FindClientByID finds a user matching the provided ID.
func FindClientByID(tx *storage.Connection, id uuid.UUID) (*Client, error) {
	return findClient(tx, "id = ?", id)
}

// FindClientsInAudience finds users with the matching audience.
func FindClientsInAudience(tx *storage.Connection, aud string, pageParams *Pagination, sortParams *SortParams, filter string) ([]*Client, error) {
	clients := []*Client{}
	q := tx.Q().Where("aud = ?", aud)

	if filter != "" {
		lf := "%" + filter + "%"
		q = q.Where("client_id LIKE ?", lf)
	}

	if sortParams != nil && len(sortParams.Fields) > 0 {
		for _, field := range sortParams.Fields {
			q = q.Order(field.Name + " " + string(field.Dir))
		}
	}

	var err error
	if pageParams != nil {
		err = q.Paginate(int(pageParams.Page), int(pageParams.PerPage)).All(&clients) // #nosec G115
		pageParams.Count = uint64(q.Paginator.TotalEntriesSize)                       // #nosec G115
	} else {
		err = q.All(&clients)
	}

	return clients, err
}

// Ban a user for a given duration.
func (c *Client) Ban(tx *storage.Connection, duration time.Duration) error {
	if duration == time.Duration(0) {
		c.BannedUntil = nil
	} else {
		t := time.Now().Add(duration)
		c.BannedUntil = &t
	}
	return tx.UpdateOnly(c, "banned_until")
}

// IsBanned checks if a user is banned or not
func (c *Client) IsBanned() bool {
	if c.BannedUntil == nil {
		return false
	}
	return time.Now().Before(*c.BannedUntil)
}

// IsDuplicatedClientID returns whether a client exists with a matching client_id and audience.
func IsDuplicatedClientID(tx *storage.Connection, clientId, aud string) (*Client, error) {
	client, err := FindClientByClientIDAndAudience(tx, clientId, aud)
	if err != nil && !IsNotFoundError(err) {
		return nil, errors.Wrap(err, "unable to find client id for duplicates")
	}

	return client, nil
}

func (c *Client) UpdateBannedUntil(tx *storage.Connection) error {
	return tx.UpdateOnly(c, "banned_until")
}

// SoftDeleteClient performs a soft deletion on the client by obfuscating and clearing certain fields
func (c *Client) SoftDeleteClient(tx *storage.Connection) error {
	c.ClientID = obfuscateClientID(c, c.GetClientID())
	c.EncryptedSecret = nil

	// set deleted_at time
	now := time.Now()
	c.DeletedAt = &now

	if err := tx.UpdateOnly(
		c,
		"client_id",
		"encrypted_secret",
		"deleted_at",
	); err != nil {
		return err
	}

	if err := ClearAllOneTimeTokensForUser(tx, c.ID); err != nil {
		return err
	}

	if err := Logout(tx, c.ID); err != nil {
		return err
	}

	return nil
}

func obfuscateClientID(u *Client, clientId string) string {
	return obfuscateValue(u.ID, clientId)
}
