-- auth.clients definition

create table if not exists {{ index .Options "Namespace" }}.clients (
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

alter table {{ index .Options "Namespace" }}.refresh_tokens
    alter column user_id drop not null;

alter table {{ index .Options "Namespace" }}.refresh_tokens
    add column client_id uuid null;

alter table {{ index .Options "Namespace" }}.refresh_tokens
    add constraint refresh_tokens_client_id_fkey
    foreign key (client_id)
    references {{ index .Options "Namespace" }}.clients(id)
    on delete cascade;

alter table {{ index .Options "Namespace" }}.sessions
    alter column user_id drop not null;

alter table {{ index .Options "Namespace" }}.sessions
    add column client_id uuid null;

alter table {{ index .Options "Namespace" }}.sessions
    add constraint sessions_client_id_fkey
    foreign key (client_id)
    references {{ index .Options "Namespace" }}.clients(id)
    on delete cascade;
