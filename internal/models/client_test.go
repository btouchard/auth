package models

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

type ClientTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *ClientTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestClient(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &ClientTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *ClientTestSuite) TestFindClientByClientIDAndAudience() {
	c := ts.createClient("client1", "secret", "test")

	n, err := FindClientByClientIDAndAudience(ts.db, c.GetClientID(), "test")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), c.ID, n.ID)

	_, err = FindClientByClientIDAndAudience(ts.db, c.GetClientID(), "invalid")
	require.EqualError(ts.T(), err, ClientNotFoundError{}.Error())
}

func (ts *ClientTestSuite) TestNewClientWithSecretHashSuccess() {
	cases := []struct {
		desc string
		hash string
	}{
		{
			desc: "Valid bcrypt hash",
			hash: "$2y$10$SXEz2HeT8PUIGQXo9yeUIem8KzNxgG0d7o/.eGj2rj8KbRgAuRVlq",
		},
		{
			desc: "Valid argon2i hash",
			hash: "$argon2i$v=19$m=16,t=2,p=1$bGJRWThNOHJJTVBSdHl2dQ$NfEnUOuUpb7F2fQkgFUG4g",
		},
		{
			desc: "Valid argon2id hash",
			hash: "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
		},
		{
			desc: "Valid Firebase scrypt hash",
			hash: "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$ZGlmZmVyZW50aGFzaA==",
		},
	}

	for i, c := range cases {
		ts.Run(c.desc, func() {
			u, err := NewClientWithSecretHash(fmt.Sprintf("client%d", i), c.hash, "")
			require.NoError(ts.T(), err)
			require.NotNil(ts.T(), u)
		})
	}
}

func (ts *ClientTestSuite) TestNewClientWithSecretHashFailure() {
	cases := []struct {
		desc string
		hash string
	}{
		{
			desc: "Invalid argon2i hash",
			hash: "$argon2id$test",
		},
		{
			desc: "Invalid bcrypt hash",
			hash: "plaintest_password",
		},
		{
			desc: "Invalid scrypt hash",
			hash: "$fbscrypt$invalid",
		},
	}

	for i, c := range cases {
		ts.Run(c.desc, func() {
			u, err := NewClientWithSecretHash(fmt.Sprintf("client%d", i), c.hash, "")
			require.Error(ts.T(), err)
			require.Nil(ts.T(), u)
		})
	}
}

func (ts *ClientTestSuite) TestAuthenticate() {
	// every case uses "test" as the password
	cases := []struct {
		desc             string
		hash             string
		expectedHashCost int
	}{
		{
			desc:             "Invalid bcrypt hash cost of 11",
			hash:             "$2y$11$4lH57PU7bGATpRcx93vIoObH3qDmft/pytbOzDG9/1WsyNmN5u4di",
			expectedHashCost: bcrypt.MinCost,
		},
		{
			desc:             "Valid bcrypt hash cost of 10",
			hash:             "$2y$10$va66S4MxFrH6G6L7BzYl0.QgcYgvSr/F92gc.3botlz7bG4p/g/1i",
			expectedHashCost: bcrypt.DefaultCost,
		},
	}

	for i, tc := range cases {
		ts.Run(tc.desc, func() {
			c, err := NewClientWithSecretHash(fmt.Sprintf("client%d", i), tc.hash, "")
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.db.Create(c))
			require.NotNil(ts.T(), c)

			isAuthenticated, _, err := c.Authenticate(context.Background(), ts.db, "test", nil, false, "")
			require.NoError(ts.T(), err)
			require.True(ts.T(), isAuthenticated)

			// check hash cost
			hashCost, err := bcrypt.Cost([]byte(*c.EncryptedSecret))
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), tc.expectedHashCost, hashCost)
		})
	}
}

func (ts *ClientTestSuite) createClient(id, secret, aud string) *Client {
	client, err := NewClient(id, secret, aud)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(client))
	return client
}
