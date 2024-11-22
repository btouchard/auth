package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type AdminClientTestSuite struct {
	suite.Suite
	Client *models.Client
	API    *API
	Config *conf.GlobalConfiguration

	token string
}

func TestAdminClient(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AdminClientTestSuite{
		API:    api,
		Config: config,
	}
	defer func() { _ = api.db.Close() }()

	suite.Run(t, ts)
}

func (ts *AdminClientTestSuite) SetupTest() {
	_ = models.TruncateAll(ts.API.db)
	claims := &AccessTokenClaims{
		Role: "supabase_admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err, "Error generating admin jwt")
	ts.token = token
}

// TestAdminClientsUnauthorized tests API /admin/clients route without authentication
func (ts *AdminClientTestSuite) TestAdminClientsUnauthorized() {
	req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusUnauthorized, w.Code)
}

// TestAdminClients tests API /admin/clients route
func (ts *AdminClientTestSuite) TestAdminClients() {
	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	assert.Equal(ts.T(), "</admin/clients?page=0>; rel=\"last\"", w.Header().Get("Link"))
	assert.Equal(ts.T(), "0", w.Header().Get("X-Total-Count"))
}

// TestAdminClients tests API /admin/clients route
func (ts *AdminClientTestSuite) TestAdminClients_Pagination() {
	c, err := models.NewClient("12345678", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	c, err = models.NewClient("987654321", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients?per_page=1", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	assert.Equal(ts.T(), "</admin/clients?page=2&per_page=1>; rel=\"next\", </admin/clients?page=2&per_page=1>; rel=\"last\"", w.Header().Get("Link"))
	assert.Equal(ts.T(), "2", w.Header().Get("X-Total-Count"))

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	for _, client := range data["clients"].([]interface{}) {
		assert.NotEmpty(ts.T(), client)
	}
}

// TestAdminClients tests API /admin/clients route
func (ts *AdminClientTestSuite) TestAdminClients_SortAsc() {
	c, err := models.NewClient("12345678", "test", ts.Config.JWT.Aud)
	c.CreatedAt = time.Now().Add(-time.Minute)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	c, err = models.NewClient("987654321", "test", ts.Config.JWT.Aud)
	c.CreatedAt = time.Now()
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	qv := req.URL.Query()
	qv.Set("sort", "created_at asc")
	req.URL.RawQuery = qv.Encode()

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Clients []*models.Client `json:"clients"`
		Aud     string           `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Clients, 2)
	assert.Equal(ts.T(), "12345678", data.Clients[0].GetClientID())
	assert.Equal(ts.T(), "987654321", data.Clients[1].GetClientID())
}

// TestAdminClients tests API /admin/clients route
func (ts *AdminClientTestSuite) TestAdminClients_SortDesc() {
	c, err := models.NewClient("12345678", "test", ts.Config.JWT.Aud)
	c.CreatedAt = time.Now().Add(-time.Minute)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	c, err = models.NewClient("987654321", "test", ts.Config.JWT.Aud)
	c.CreatedAt = time.Now()
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Clients []*models.Client `json:"clients"`
		Aud     string           `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Clients, 2)
	assert.Equal(ts.T(), "987654321", data.Clients[0].GetClientID())
	assert.Equal(ts.T(), "12345678", data.Clients[1].GetClientID())
}

// TestAdminClients tests API /admin/clients route
func (ts *AdminClientTestSuite) TestAdminClients_FilterClientID() {
	c, err := models.NewClient("12345678", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients?filter=1234", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Clients []*models.Client `json:"clients"`
		Aud     string           `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Clients, 1)
	assert.Equal(ts.T(), "12345678", data.Clients[0].GetClientID())
}

// TestAdminClientCreate tests API /admin/client route (POST)
func (ts *AdminClientTestSuite) TestAdminClientCreate() {
	cases := []struct {
		desc     string
		params   map[string]interface{}
		expected map[string]interface{}
	}{
		{
			desc: "With secret",
			params: map[string]interface{}{
				"client_id":     "123456789abc",
				"client_secret": "test",
			},
			expected: map[string]interface{}{
				"client_id":       "123456789abc",
				"secret":          "test",
				"isAuthenticated": true,
				"provider":        "client_secret",
			},
		},
		{
			desc: "Ban created client",
			params: map[string]interface{}{
				"client_id":     "123456789abc",
				"client_secret": "test",
				"ban_duration":  "24h",
			},
			expected: map[string]interface{}{
				"client_id":       "123456789abc",
				"secret":          "test",
				"isAuthenticated": true,
				"provider":        "client_secret",
			},
		},
		{
			desc: "With password hash",
			params: map[string]interface{}{
				"client_id":          "123456789abc",
				"client_secret_hash": "$2y$10$SXEz2HeT8PUIGQXo9yeUIem8KzNxgG0d7o/.eGj2rj8KbRgAuRVlq",
			},
			expected: map[string]interface{}{
				"client_id":       "123456789abc",
				"secret":          "test",
				"isAuthenticated": true,
				"provider":        "client_secret",
			},
		},
		{
			desc: "With custom id",
			params: map[string]interface{}{
				"id":            "fc56ab41-2010-4870-a9b9-767c1dc573fb",
				"client_id":     "123456789abc",
				"client_secret": "test",
			},
			expected: map[string]interface{}{
				"id":              "fc56ab41-2010-4870-a9b9-767c1dc573fb",
				"client_id":       "123456789abc",
				"secret":          "test",
				"isAuthenticated": true,
				"provider":        "client_secret",
			},
		},
	}

	for _, tc := range cases {
		ts.Run(tc.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(tc.params))

			// Setup request
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/clients", &buffer)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)

			data := models.Client{}
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			assert.Equal(ts.T(), tc.expected["client_id"], data.GetClientID())

			c, err := models.FindClientByID(ts.API.db, data.ID)
			require.NoError(ts.T(), err)

			if _, ok := tc.expected["secret"]; ok {
				expectedPassword := fmt.Sprintf("%v", tc.expected["secret"])
				isAuthenticated, _, err := c.Authenticate(context.Background(), ts.API.db, expectedPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
				require.NoError(ts.T(), err)
				require.Equal(ts.T(), tc.expected["isAuthenticated"], isAuthenticated)
			}

			if id, ok := tc.expected["id"]; ok {
				uid, err := uuid.FromString(id.(string))
				require.NoError(ts.T(), err)
				require.Equal(ts.T(), uid, data.ID)
			}

			// remove created client after each case
			require.NoError(ts.T(), ts.API.db.Destroy(c))
		})
	}
}

func (ts *AdminClientTestSuite) TestAdminClientCreateValidationErrors() {
	cases := []struct {
		desc   string
		params map[string]interface{}
	}{
		{
			desc: "create client without client id",
			params: map[string]interface{}{
				"client_secret": "test_password",
			},
		},
		{
			desc: "create client with secret and secret hash",
			params: map[string]interface{}{
				"client_id":   "123456789abc",
				"secret":      "test_password",
				"secret_hash": "$2y$10$Tk6yEdmTbb/eQ/haDMaCsuCsmtPVprjHMcij1RqiJdLGPDXnL3L1a",
			},
		},
		{
			desc: "invalid ban duration",
			params: map[string]interface{}{
				"client_id":    "123456789abc",
				"ban_duration": "never",
			},
		},
		{
			desc: "custom id is nil",
			params: map[string]interface{}{
				"id":        "00000000-0000-0000-0000-000000000000",
				"client_id": "123456789abc",
			},
		},
		{
			desc: "bad id format",
			params: map[string]interface{}{
				"id":        "bad_uuid_format",
				"client_id": "123456789abc",
			},
		},
	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.params))
			req := httptest.NewRequest(http.MethodPost, "/admin/clients", &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusBadRequest, w.Code, w)

			data := map[string]interface{}{}
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			require.Equal(ts.T(), data["error_code"], ErrorCodeValidationFailed)
		})

	}
}

// TestAdminClientGet tests API /admin/client route (GET)
func (ts *AdminClientTestSuite) TestAdminClientGet() {
	u, err := models.NewClient("123456789abc", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating client")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/clients/%s", u.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	assert.Equal(ts.T(), data["client_id"], "123456789abc")
}

// TestAdminClientUpdate tests API /admin/client route (UPDATE)
func (ts *AdminClientTestSuite) TestAdminClientUpdate() {
	c, err := models.NewClient("123456789abc", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	var buffer bytes.Buffer
	newClientID := "abc123456789"
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"role":         "testing",
		"ban_duration": "24h",
		"client_id":    newClientID,
	}))

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/admin/clients/%s", c.ID), &buffer)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := models.Client{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	assert.Equal(ts.T(), "testing", data.Role)
	assert.Equal(ts.T(), newClientID, data.GetClientID())
	assert.NotNil(ts.T(), data.BannedUntil)

	c, err = models.FindClientByID(ts.API.db, data.ID)
	require.NoError(ts.T(), err)
}

func (ts *AdminClientTestSuite) TestAdminClientUpdateSecretFailed() {
	c, err := models.NewClient("123456789abc", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	var updateEndpoint = fmt.Sprintf("/admin/clients/%s", c.ID)
	ts.Config.Secret.MinLength = 10
	ts.Run("Secret doesn't meet minimum password length", func() {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"client_secret": "12345",
		}))

		// Setup request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, updateEndpoint, &buffer)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)
	})
}

func (ts *AdminClientTestSuite) TestAdminClientUpdateBannedUntilFailed() {
	c, err := models.NewClient("123456789abc", "test", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error making new client")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

	var updateEndpoint = fmt.Sprintf("/admin/clients/%s", c.ID)
	ts.Config.Password.MinLength = 6
	ts.Run("Incorrect format for ban_duration", func() {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"ban_duration": "24",
		}))

		// Setup request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, updateEndpoint, &buffer)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code)
	})
}

// TestAdminClientDelete tests API /admin/clients route (DELETE)
func (ts *AdminClientTestSuite) TestAdminClientDelete() {
	type expected struct {
		code int
		err  error
	}
	cases := []struct {
		desc         string
		body         map[string]interface{}
		isSoftDelete string
		expected     expected
	}{
		{
			desc:         "Test admin delete client (default)",
			isSoftDelete: "",
			expected:     expected{code: http.StatusOK, err: models.ClientNotFoundError{}},
			body:         nil,
		},
		{
			desc:         "Test admin delete client (hard deletion)",
			isSoftDelete: "?is_soft_delete=false",
			expected:     expected{code: http.StatusOK, err: models.ClientNotFoundError{}},
			body: map[string]interface{}{
				"should_soft_delete": false,
			},
		},
		{
			desc:         "Test admin delete client (soft deletion)",
			isSoftDelete: "?is_soft_delete=true",
			expected:     expected{code: http.StatusOK, err: models.ClientNotFoundError{}},
			body: map[string]interface{}{
				"should_soft_delete": true,
			},
		},
	}

	for _, tc := range cases {
		ts.Run(tc.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(tc.body))

			c, err := models.NewClient("123456789abc", "test", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err, "Error making new client")
			require.NoError(ts.T(), ts.API.db.Create(c), "Error creating client")

			// Setup request
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/clients/%s", c.ID), &buffer)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), tc.expected.code, w.Code)

			_, err = models.FindClientByClientIDAndAudience(ts.API.db, c.ClientID, ts.Config.JWT.Aud)
			require.Equal(ts.T(), tc.expected.err, err)
		})
	}
}
