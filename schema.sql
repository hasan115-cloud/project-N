-- ════════════════════════════════════════════════════════════════════════════
--  PhishGuard — Supabase / PostgreSQL schema  (schema_version 2)
--
--  HOW TO RUN: Supabase Dashboard → SQL Editor → New query → paste this whole
--  file → Run.  It is IDEMPOTENT: safe on a brand-new project AND safe to
--  re-run on a project that already has PhishGuard tables (it upgrades them in
--  place and never drops or truncates a row).
--
--  The server (Netlify Function) connects with DATABASE_URL and NEVER creates
--  or alters tables at runtime — this file is the single source of truth for
--  the schema. If it has not been applied, the API answers HTTP 503 with a
--  clear message instead of silently using some other store.
-- ════════════════════════════════════════════════════════════════════════════

begin;

create extension if not exists pg_trgm;   -- fast substring search in URL History

-- ── schema version marker (server checks this on startup) ───────────────────
create table if not exists schema_meta (
  key   text primary key,
  value text not null
);

-- ── enrolled systems (one row per installed extension) ──────────────────────
create table if not exists clients (
  id                text primary key,                 -- stable extension-generated id
  client_name       text not null,
  first_seen        timestamptz not null default now(),
  last_seen         timestamptz not null default now(),
  status            text not null default 'ENROLLED',
  extension_version text,
  browser           text,
  os                text,
  platform          text,
  ip                text
);
alter table clients add column if not exists token_hash text;            -- sha-256 of the per-system API token
alter table clients add column if not exists last_stats jsonb;           -- last heartbeat counters (diagnostic only)
alter table clients add column if not exists created_at timestamptz not null default now();
alter table clients add column if not exists updated_at timestamptz not null default now();

-- ── URL scan / navigation history ───────────────────────────────────────────
create table if not exists url_events (
  id             text primary key,
  event_id       text,                                -- client-minted idempotency key
  client_id      text not null,
  client_name    text,
  url            text not null,
  domain         text,
  classification text not null,                       -- SAFE | SUSPICIOUS | PHISHING
  verdict        text not null,                       -- action: ALLOWED | WARNING | BLOCKED
  score          double precision,
  reason         text,
  source         text,
  rule_triggered boolean default false,
  rule_type      text,                                -- WHITELIST | PHISHING (blacklist)
  occurred_at    timestamptz not null default now()
);
alter table url_events add column if not exists normalized_url  text;
alter table url_events add column if not exists matched_rule_id text;    -- no FK on purpose: history must outlive a deleted rule
alter table url_events add column if not exists matched_pattern text;    -- the pattern text as it was when matched
alter table url_events add column if not exists decision_source text;    -- rule | safe-list | heuristic | trusted
alter table url_events add column if not exists received_at    timestamptz not null default now();

-- ── threat alerts ───────────────────────────────────────────────────────────
create table if not exists threat_alerts (
  id          text primary key,
  client_id   text not null,
  client_name text,
  url         text not null,
  domain      text,
  score       double precision,
  reasons     jsonb,
  source      text,
  status      text not null default 'ACTIVE',
  occurred_at timestamptz not null default now()
);
alter table threat_alerts add column if not exists event_id        text;   -- same key as url_events.event_id → one alert per detection
alter table threat_alerts add column if not exists matched_rule_id text;
alter table threat_alerts add column if not exists matched_pattern text;
alter table threat_alerts add column if not exists rule_type       text;
alter table threat_alerts add column if not exists action          text not null default 'BLOCKED';
alter table threat_alerts add column if not exists updated_at      timestamptz not null default now();

-- ── security rules ──────────────────────────────────────────────────────────
create table if not exists whitelist_rules (
  id          text primary key,
  pattern     text not null unique,
  description text,
  added_by    text,
  created_at  timestamptz not null default now()
);
alter table whitelist_rules add column if not exists enabled    boolean not null default true;
alter table whitelist_rules add column if not exists updated_at timestamptz not null default now();

create table if not exists phishing_rules (
  id         text primary key,
  pattern    text not null unique,
  severity   text not null,
  reason     text,
  added_by   text,
  created_at timestamptz not null default now()
);
alter table phishing_rules add column if not exists enabled    boolean not null default true;
alter table phishing_rules add column if not exists updated_at timestamptz not null default now();

-- ── rules version: bumped on ANY rule change so extensions only re-download
--    rules when something actually changed (no repeated full downloads) ─────
create table if not exists rules_meta (
  id         smallint primary key default 1 check (id = 1),
  version    bigint not null default 1,
  updated_at timestamptz not null default now()
);
insert into rules_meta (id) values (1) on conflict (id) do nothing;

-- ════════════════════════════════════════════════════════════════════════════
--  Repair data from earlier versions BEFORE adding foreign keys
-- ════════════════════════════════════════════════════════════════════════════

-- Older servers accepted events/alerts for a client id without a clients row.
-- Recreate a placeholder system for each so no history is lost or orphaned.
insert into clients (id, client_name, first_seen, last_seen, status)
select e.client_id,
       coalesce(max(e.client_name), 'Recovered system'),
       min(e.occurred_at), max(e.occurred_at), 'ENROLLED'
from url_events e
where not exists (select 1 from clients c where c.id = e.client_id)
group by e.client_id
on conflict (id) do nothing;

insert into clients (id, client_name, first_seen, last_seen, status)
select a.client_id,
       coalesce(max(a.client_name), 'Recovered system'),
       min(a.occurred_at), max(a.occurred_at), 'ENROLLED'
from threat_alerts a
where not exists (select 1 from clients c where c.id = a.client_id)
group by a.client_id
on conflict (id) do nothing;

-- ════════════════════════════════════════════════════════════════════════════
--  Constraints (guarded so re-running is a no-op)
-- ════════════════════════════════════════════════════════════════════════════
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'fk_url_events_client') then
    alter table url_events add constraint fk_url_events_client
      foreign key (client_id) references clients(id) on delete cascade;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'fk_threat_alerts_client') then
    alter table threat_alerts add constraint fk_threat_alerts_client
      foreign key (client_id) references clients(id) on delete cascade;
  end if;

  -- NOT VALID = enforced for every new/updated row without rescanning old rows.
  if not exists (select 1 from pg_constraint where conname = 'ck_url_events_classification') then
    alter table url_events add constraint ck_url_events_classification
      check (classification in ('SAFE','SUSPICIOUS','PHISHING')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'ck_url_events_verdict') then
    alter table url_events add constraint ck_url_events_verdict
      check (verdict in ('ALLOWED','WARNING','BLOCKED')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'ck_url_events_rule_type') then
    alter table url_events add constraint ck_url_events_rule_type
      check (rule_type is null or rule_type in ('WHITELIST','PHISHING')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'ck_threat_alerts_status') then
    alter table threat_alerts add constraint ck_threat_alerts_status
      check (status in ('ACTIVE','ACKNOWLEDGED','RESOLVED')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'ck_phishing_rules_severity') then
    alter table phishing_rules add constraint ck_phishing_rules_severity
      check (severity in ('HIGH','CRITICAL')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'ck_clients_status') then
    alter table clients add constraint ck_clients_status
      check (status in ('ENROLLED')) not valid;
  end if;
end $$;

-- ════════════════════════════════════════════════════════════════════════════
--  Indexes
-- ════════════════════════════════════════════════════════════════════════════

-- Idempotency: one row per (system, event id). Replaces the older GLOBAL
-- unique index on event_id alone, which let one system's id block another's.
drop index if exists uq_url_events_event_id;
create unique index if not exists uq_url_events_client_event
  on url_events (client_id, event_id) where event_id is not null;

-- URL History: newest-first, optionally per system / classification.
drop index if exists idx_url_events_client;
drop index if exists idx_url_events_occurred_at;
create index if not exists idx_url_events_time         on url_events (occurred_at desc, id desc);
create index if not exists idx_url_events_client_time  on url_events (client_id, occurred_at desc, id desc);
create index if not exists idx_url_events_class_time   on url_events (classification, occurred_at desc);
create index if not exists idx_url_events_client_class on url_events (client_id, classification);
create index if not exists idx_url_events_rule         on url_events (matched_rule_id) where matched_rule_id is not null;
-- Search box (ILIKE '%text%') on URL / domain.
create index if not exists idx_url_events_url_trgm     on url_events using gin (url gin_trgm_ops);
create index if not exists idx_url_events_domain_trgm  on url_events using gin (domain gin_trgm_ops);

-- Alerts: one alert per detection, fast list + active count.
create unique index if not exists uq_threat_alerts_client_event
  on threat_alerts (client_id, event_id) where event_id is not null;
drop index if exists idx_threat_alerts_client;
drop index if exists idx_threat_alerts_status;
create index if not exists idx_threat_alerts_time        on threat_alerts (occurred_at desc, id desc);
create index if not exists idx_threat_alerts_client_time on threat_alerts (client_id, occurred_at desc);
create index if not exists idx_threat_alerts_active      on threat_alerts (client_id) where status = 'ACTIVE';

-- Systems list.
create index if not exists idx_clients_first_seen on clients (first_seen desc);

-- ════════════════════════════════════════════════════════════════════════════
--  Triggers
-- ════════════════════════════════════════════════════════════════════════════
create or replace function pg_set_updated_at() returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

create or replace function pg_bump_rules_version() returns trigger language plpgsql as $$
begin
  update rules_meta set version = version + 1, updated_at = now() where id = 1;
  return null;
end $$;

drop trigger if exists trg_whitelist_updated on whitelist_rules;
create trigger trg_whitelist_updated before update on whitelist_rules
  for each row execute function pg_set_updated_at();
drop trigger if exists trg_phishing_updated on phishing_rules;
create trigger trg_phishing_updated before update on phishing_rules
  for each row execute function pg_set_updated_at();
drop trigger if exists trg_alerts_updated on threat_alerts;
create trigger trg_alerts_updated before update on threat_alerts
  for each row execute function pg_set_updated_at();

drop trigger if exists trg_whitelist_version on whitelist_rules;
create trigger trg_whitelist_version after insert or update or delete on whitelist_rules
  for each statement execute function pg_bump_rules_version();
drop trigger if exists trg_phishing_version on phishing_rules;
create trigger trg_phishing_version after insert or update or delete on phishing_rules
  for each statement execute function pg_bump_rules_version();

-- ════════════════════════════════════════════════════════════════════════════
--  Row Level Security
--  The API server connects with the database owner role (DATABASE_URL), which
--  bypasses RLS. Enabling RLS with NO policies means the public `anon` and
--  `authenticated` keys (Supabase REST API) can read/write NOTHING here, so
--  even if the anon key leaks, no PhishGuard data is exposed.
-- ════════════════════════════════════════════════════════════════════════════
alter table schema_meta     enable row level security;
alter table clients         enable row level security;
alter table url_events      enable row level security;
alter table threat_alerts   enable row level security;
alter table whitelist_rules enable row level security;
alter table phishing_rules  enable row level security;
alter table rules_meta      enable row level security;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    revoke all on schema_meta, clients, url_events, threat_alerts, whitelist_rules, phishing_rules, rules_meta from anon;
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    revoke all on schema_meta, clients, url_events, threat_alerts, whitelist_rules, phishing_rules, rules_meta from authenticated;
  end if;
end $$;

-- ── mark schema applied ─────────────────────────────────────────────────────
insert into schema_meta (key, value) values ('schema_version', '2')
on conflict (key) do update set value = excluded.value;

commit;

-- Optional (NOT run automatically): supabase/migrations_optional_cleanup.sql
-- removes rows that older extension versions recorded for page links the user never visited.
