-- Run with psql as the administrator of the dedicated serving database.
-- Passwords come from the caller's environment, never command arguments.
\set ON_ERROR_STOP on
\getenv service_password FG_NATIVE_SERVICE_PASSWORD
\getenv gc_password FG_NATIVE_GC_PASSWORD
\getenv branch_password FG_NATIVE_BRANCH_PASSWORD
SELECT format('CREATE ROLE fg_service LOGIN PASSWORD %L', :'service_password') \gexec
SELECT format('CREATE ROLE fg_gc LOGIN PASSWORD %L', :'gc_password') \gexec
SELECT format('CREATE ROLE fg_branch_admin LOGIN PASSWORD %L', :'branch_password') \gexec
SELECT format('GRANT CREATE ON DATABASE %I TO fg_branch_admin', current_database()) \gexec
