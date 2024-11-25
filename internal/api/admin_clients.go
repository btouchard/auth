package api

import (
	"context"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type AdminClientParams struct {
	Id               string  `json:"id"`
	Aud              string  `json:"aud"`
	Role             string  `json:"role"`
	ClientID         string  `json:"client_id"`
	ClientSecret     *string `json:"client_secret"`
	ClientSecretHash string  `json:"client_secret_hash"`
	BanDuration      string  `json:"ban_duration"`
}

type adminClientDeleteParams struct {
	ShouldSoftDelete bool `json:"should_soft_delete"`
}

type AdminListClientsResponse struct {
	Clients []*models.Client `json:"clients"`
	Aud     string           `json:"aud"`
}

func (a *API) loadClient(_ http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	clientID, err := uuid.FromString(chi.URLParam(r, "client_id"))
	if err != nil {
		return nil, notFoundError(ErrorCodeValidationFailed, "client_id must be an UUID")
	}

	observability.LogEntrySetField(r, "client_id", clientID)

	c, err := models.FindClientByID(db, clientID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(ErrorCodeClientNotFound, "Client not found")
		}
		return nil, internalServerError("Database error loading client").WithInternalError(err)
	}

	return withClient(ctx, c), nil
}

func (a *API) getAdminClientParams(r *http.Request) (*AdminClientParams, error) {
	params := &AdminClientParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return nil, err
	}

	return params, nil
}

// adminClients responds with a list of all clients in a given audience
func (a *API) adminClients(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	pageParams, err := paginate(r)
	if err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Bad Pagination Parameters: %v", err).WithInternalError(err)
	}

	sortParams, err := sort(r, map[string]bool{models.CreatedAt: true}, []models.SortField{{Name: models.CreatedAt, Dir: models.Descending}})
	if err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Bad Sort Parameters: %v", err)
	}

	filter := r.URL.Query().Get("filter")

	clients, err := models.FindClientsInAudience(db, aud, pageParams, sortParams, filter)
	if err != nil {
		return internalServerError("Database error finding clients").WithInternalError(err)
	}
	addPaginationHeaders(w, r, pageParams)

	return sendJSON(w, http.StatusOK, AdminListClientsResponse{
		Clients: clients,
		Aud:     aud,
	})
}

// adminClientGet returns information about a single client
func (a *API) adminClientGet(w http.ResponseWriter, r *http.Request) error {
	client := getClient(r.Context())

	return sendJSON(w, http.StatusOK, client)
}

// adminClientUpdate updates a single client object
func (a *API) adminClientUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	client := getClient(ctx)
	adminUser := getAdminUser(ctx)
	params, err := a.getAdminClientParams(r)
	if err != nil {
		return err
	}

	if params.ClientID != "" {
		params.ClientID, err = a.validateClientID(params.ClientID)
		if err != nil {
			return err
		}
	}

	if params.ClientSecret != nil {
		pwd := *params.ClientSecret

		if err := a.checkSecretStrength(ctx, pwd); err != nil {
			return err
		}

		if err := client.SetSecret(ctx, pwd, config.Security.DBEncryption.Encrypt, config.Security.DBEncryption.EncryptionKeyID, config.Security.DBEncryption.EncryptionKey); err != nil {
			return err
		}
	}

	var banDuration *time.Duration
	if params.BanDuration != "" {
		duration := time.Duration(0)
		if params.BanDuration != "none" {
			duration, err = time.ParseDuration(params.BanDuration)
			if err != nil {
				return badRequestError(ErrorCodeValidationFailed, "invalid format for ban duration: %v", err)
			}
		}
		banDuration = &duration
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if params.Role != "" {
			if terr := client.SetRole(tx, params.Role); terr != nil {
				return terr
			}
		}

		if params.ClientID != "" {
			if terr := client.SetClientID(tx, params.ClientID); terr != nil {
				return terr
			}
		}

		if params.ClientSecret != nil {
			if terr := client.UpdateSecret(tx, nil); terr != nil {
				return terr
			}
		}

		if banDuration != nil {
			if terr := client.Ban(tx, *banDuration); terr != nil {
				return terr
			}
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.ClientModifiedAction, "", map[string]interface{}{
			"client_id":        client.ID,
			"client_client_id": client.ClientID,
		}); terr != nil {
			return terr
		}
		return nil
	})

	if err != nil {
		return internalServerError("Error updating client").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, client)
}

// adminClientCreate creates a new client based on the provided data
func (a *API) adminClientCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	adminUser := getAdminUser(ctx)
	params, err := a.getAdminClientParams(r)
	if err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	if params.Aud != "" {
		aud = params.Aud
	}

	if params.ClientID == "" {
		return badRequestError(ErrorCodeValidationFailed, "Cannot create a client without either an client id")
	}

	var providers []string
	if params.ClientID != "" {
		params.ClientID, err = a.validateClientID(params.ClientID)
		if err != nil {
			return err
		}
		if client, err := models.IsDuplicatedClientID(db, params.ClientID, aud); err != nil {
			return internalServerError("Database error checking client id").WithInternalError(err)
		} else if client != nil {
			return unprocessableEntityError(ErrorCodeClientIDExists, DuplicateClientIDMsg)
		}
		providers = append(providers, "client_credentials")
	}

	if params.ClientSecret == nil && params.ClientSecretHash == "" {
		return badRequestError(ErrorCodeValidationFailed, "Missing secret or secret hash")
	} else if params.ClientSecret != nil && params.ClientSecretHash != "" {
		return badRequestError(ErrorCodeValidationFailed, "Only a one of secret or a secret hash should be provided")
	}

	var client *models.Client
	if params.ClientSecretHash != "" {
		client, err = models.NewClientWithSecretHash(params.ClientID, params.ClientSecretHash, aud)
	} else {
		client, err = models.NewClient(params.ClientID, *params.ClientSecret, aud)
	}

	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return badRequestError(ErrorCodeValidationFailed, err.Error())
		}
		return internalServerError("Error creating client").WithInternalError(err)
	}

	if params.Id != "" {
		customId, err := uuid.FromString(params.Id)
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "ID must conform to the uuid v4 format")
		}
		if customId == uuid.Nil {
			return badRequestError(ErrorCodeValidationFailed, "ID cannot be a nil uuid")
		}
		client.ID = customId
	}

	var banDuration *time.Duration
	if params.BanDuration != "" {
		duration := time.Duration(0)
		if params.BanDuration != "none" {
			duration, err = time.ParseDuration(params.BanDuration)
			if err != nil {
				return badRequestError(ErrorCodeValidationFailed, "invalid format for ban duration: %v", err)
			}
		}
		banDuration = &duration
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(client); terr != nil {
			return terr
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.ClientRegistrationAction, "", map[string]interface{}{
			"client_id":        client.ID,
			"client_client_id": client.ClientID,
		}); terr != nil {
			return terr
		}

		role := config.JWT.DefaultGroupName
		if params.Role != "" {
			role = params.Role
		}

		if banDuration != nil {
			if terr := client.Ban(tx, *banDuration); terr != nil {
				return terr
			}
		}

		if terr := client.SetRole(tx, role); terr != nil {
			return terr
		}

		return nil
	})

	if err != nil {
		return internalServerError("Database error creating new client").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, client)
}

// adminClientDelete deletes a client
func (a *API) adminClientDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := getClient(ctx)
	adminUser := getAdminUser(ctx)

	// ShouldSoftDelete defaults to false
	params := &adminClientDeleteParams{}
	if body, _ := utilities.GetBodyBytes(r); len(body) != 0 {
		// we only want to parse the body if it's not empty
		// retrieveRequestParams will handle any errors with stream
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}

	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.ClientDeletedAction, "", map[string]interface{}{
			"client_id":        client.ID,
			"client_client_id": client.ClientID,
		}); terr != nil {
			return internalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if params.ShouldSoftDelete {
			if client.DeletedAt != nil {
				// client has been soft deleted already
				return nil
			}
			if terr := client.SoftDeleteClient(tx); terr != nil {
				return internalServerError("Error soft deleting client").WithInternalError(terr)
			}
			// hard delete all associated sessions
			if terr := models.Logout(tx, client.ID); terr != nil {
				return internalServerError("Error deleting client's sessions").WithInternalError(terr)
			}
		} else {
			if terr := tx.Destroy(client); terr != nil {
				return internalServerError("Database error deleting client").WithInternalError(terr)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{})
}
