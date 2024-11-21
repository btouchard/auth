-- auth.clients definition

CREATE TABLE IF NOT EXISTS {{ index .Options "Namespace" }}.clients (
    instance_id uuid NULL,
    id uuid NOT NULL UNIQUE,
    aud varchar(255) NULL,
    "role" varchar(255) NULL,
    client_id varchar(255) NULL UNIQUE,
    encrypted_secret varchar(255) NULL,
    last_sign_in_at timestamptz NULL,
    banned_until timestamptz NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    deleted_at timestamptz null,
    CONSTRAINT clients_pkey PRIMARY KEY (id)
    );

comment on table {{ index .Options "Namespace" }}.clients is 'Auth: Stores client data within a secure schema.';