package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
)

const (
	username    = "p1_user"
	branch      = "p1-fixture"
	frontCA     = "/p1-tls/frontend-ca.pem"
	wrongCA     = "/p1-tls/backend-ca.pem"
	refusedSQL  = "DROP TABLE fixture_items"
	countEvents = "SELECT COUNT(*) FROM fixture_events"
	insertEvent = "INSERT INTO fixture_events (id) VALUES (1)"
)

var password = os.Getenv("FG_P1_FRONTEND_PASSWORD")

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func check(condition bool, name string) {
	if !condition {
		panic(name)
	}
	fmt.Println("case", name, "PASS")
}

func rejected(err error, marker, name string) {
	if err == nil || !strings.Contains(err.Error(), marker) {
		panic(fmt.Sprintf("%s: expected %q, received %v", name, marker, err))
	}
	check(true, name)
}

func printVersion(packageName string) {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		panic("missing Go dependency build info")
	}
	for _, dependency := range build.Deps {
		if dependency.Path == packageName {
			fmt.Println("version", dependency.Path, dependency.Version, runtime.Version())
			return
		}
	}
	panic("missing Go driver version")
}

func mysqlConnect(ctx context.Context, auth, database, ca string) (*sql.DB, error) {
	certificate, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, fmt.Errorf("invalid root CA")
	}
	config := mysql.NewConfig()
	config.User = username
	config.Passwd = auth
	config.Net = "tcp"
	config.Addr = "localhost:13306"
	config.DBName = database
	config.TLS = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	config.Timeout = 5 * time.Second
	config.ReadTimeout = 5 * time.Second
	connector, err := mysql.NewConnector(config)
	if err != nil {
		return nil, err
	}
	databaseHandle := sql.OpenDB(connector)
	databaseHandle.SetMaxOpenConns(1)
	if err := databaseHandle.PingContext(ctx); err != nil {
		databaseHandle.Close()
		return nil, err
	}
	return databaseHandle, nil
}

func mysqlProbe(ctx context.Context) {
	printVersion("github.com/go-sql-driver/mysql")
	_, err := mysqlConnect(ctx, "wrong-password", branch, frontCA)
	rejected(err, "FG-1002", "wrong-password")
	_, err = mysqlConnect(ctx, password, "other-branch", frontCA)
	rejected(err, "FG-2003", "unauthorized-branch")
	_, err = mysqlConnect(ctx, password, "", frontCA)
	rejected(err, "FG-2003", "missing-branch")
	_, err = mysqlConnect(ctx, password, branch, wrongCA)
	rejected(err, "certificate", "wrong-ca")

	databaseHandle, err := mysqlConnect(ctx, password, branch, frontCA)
	must(err)
	var value int
	must(databaseHandle.QueryRowContext(ctx, "SELECT 1").Scan(&value))
	check(value == 1, "verified-tls-and-select")
	_, err = databaseHandle.ExecContext(ctx, refusedSQL)
	rejected(err, "FG-2002", "unsupported-sql")
	mysqlPrepared(ctx, databaseHandle)
	_, err = databaseHandle.ExecContext(ctx, "START TRANSACTION")
	must(err)
	_, err = databaseHandle.ExecContext(ctx, insertEvent)
	must(err)
	must(databaseHandle.QueryRowContext(ctx, countEvents).Scan(&value))
	check(value == 1, "transaction-visibility")
	must(databaseHandle.Close())
	databaseHandle, err = mysqlConnect(ctx, password, branch, frontCA)
	must(err)
	defer databaseHandle.Close()
	must(databaseHandle.QueryRowContext(ctx, countEvents).Scan(&value))
	check(value == 0, "disconnect-rollback")
}

func mysqlPrepared(ctx context.Context, databaseHandle *sql.DB) {
	prepared, err := databaseHandle.PrepareContext(ctx, "SELECT id, payload FROM fixture_items WHERE id = ?")
	must(err)
	defer prepared.Close()
	for index, expected := range [][]byte{nil, {}, {0, 255, 65}} {
		var id int
		var payload []byte
		must(prepared.QueryRowContext(ctx, index+1).Scan(&id, &payload))
		check(id == index+1 && bytes.Equal(payload, expected) && (payload == nil) == (expected == nil),
			fmt.Sprintf("prepared-reuse-%d", id))
	}
	var id int
	err = prepared.QueryRowContext(ctx).Scan(&id)
	rejected(err, "expected 1 arguments", "incorrect-binding")
}

func postgresConnect(ctx context.Context, auth, database, ca string) (*pgx.Conn, error) {
	options := fmt.Sprintf("host=localhost port=15432 user=%s dbname=%s sslmode=verify-full sslrootcert=%s connect_timeout=5", username, database, ca)
	config, err := pgx.ParseConfig(options)
	if err != nil {
		return nil, err
	}
	config.Password = auth
	return pgx.ConnectConfig(ctx, config)
}

func postgresProbe(ctx context.Context) {
	printVersion("github.com/jackc/pgx/v5")
	_, err := postgresConnect(ctx, "wrong-password", branch, frontCA)
	rejected(err, "FG-1002", "wrong-password")
	_, err = postgresConnect(ctx, password, "other-branch", frontCA)
	rejected(err, "FG-2003", "unauthorized-branch")
	_, err = postgresConnect(ctx, password, branch, wrongCA)
	rejected(err, "certificate", "wrong-ca")

	connection, err := postgresConnect(ctx, password, branch, frontCA)
	must(err)
	var value int
	must(connection.QueryRow(ctx, "SELECT 1").Scan(&value))
	check(value == 1, "verified-tls-and-select")
	_, err = connection.Exec(ctx, refusedSQL)
	rejected(err, "FG-2002", "unsupported-sql")
	postgresPrepared(ctx, connection)
	_, err = connection.Exec(ctx, "BEGIN")
	must(err)
	_, err = connection.Exec(ctx, insertEvent)
	must(err)
	must(connection.QueryRow(ctx, countEvents).Scan(&value))
	check(value == 1, "transaction-visibility")
	must(connection.Close(ctx))
	connection, err = postgresConnect(ctx, password, branch, frontCA)
	must(err)
	defer connection.Close(ctx)
	must(connection.QueryRow(ctx, countEvents).Scan(&value))
	check(value == 0, "disconnect-rollback")
}

func postgresPrepared(ctx context.Context, connection *pgx.Conn) {
	const statementName = "fixture_named"
	_, err := connection.Prepare(ctx, statementName, "SELECT id, payload FROM fixture_items WHERE id = $1")
	must(err)
	for index, expected := range [][]byte{nil, {}, {0, 255, 65}} {
		var id int
		var payload []byte
		must(connection.QueryRow(ctx, statementName, index+1).Scan(&id, &payload))
		check(id == index+1 && bytes.Equal(payload, expected) && (payload == nil) == (expected == nil),
			fmt.Sprintf("prepared-reuse-%d", id))
	}
	must(connection.Deallocate(ctx, statementName))
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch os.Args[1] {
	case "mysql", "tidb":
		mysqlProbe(ctx)
	case "postgresql":
		postgresProbe(ctx)
	default:
		panic("unknown engine")
	}
}
