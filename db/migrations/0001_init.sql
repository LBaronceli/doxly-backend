create extension if not exists "uuid-ossp";
create extension if not exists "citext";

create table organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table users (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  email citext not null unique,
  password_hash text not null,
  role text not null check (role in ('admin','member')),
  created_at timestamptz not null default now()
);

create table customers (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  email citext unique,
  tags text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table notes (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  customer_id uuid not null references customers(id) on delete cascade,
  author_user_id uuid not null references users(id) on delete set null,
  body text not null,
  created_at timestamptz not null default now()
);

create table attachments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  customer_id uuid not null references customers(id) on delete cascade,
  key text not null,
  filename text not null,
  content_type text,
  size_bytes bigint,
  checksum text,
  uploaded_by uuid not null references users(id),
  created_at timestamptz not null default now()
);

create index if not exists idx_customers_org_created on customers(org_id, created_at desc);
create index if not exists idx_notes_org_customer_created on notes(org_id, customer_id, created_at desc);
create index if not exists idx_attachments_org_customer_created on attachments(org_id, customer_id, created_at desc);
