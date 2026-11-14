import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Locale;
import java.util.Properties;

class Probe {
    private static final String USER = "p1_user";
    private static final String BRANCH = "p1-fixture";
    private static final String PASSWORD = System.getenv("FG_P1_FRONTEND_PASSWORD");
    private static final String SELECT_ITEM = "SELECT id, payload FROM fixture_items WHERE id = ?";
    private static final String INSERT_EVENT = "INSERT INTO fixture_events (id) VALUES (1)";
    private static final String COUNT_EVENTS = "SELECT COUNT(*) FROM fixture_events";

    public static void main(String[] args) throws Exception {
        // TiDB serves the MySQL wire protocol.
        boolean mysql = switch (args[0]) {
            case "mysql", "tidb" -> true;
            case "postgresql" -> false;
            default -> throw new IllegalArgumentException("Unknown engine");
        };
        Class.forName(mysql ? "com.mysql.cj.jdbc.Driver" : "org.postgresql.Driver");
        Driver driver = DriverManager.getDriver(url(mysql, BRANCH));
        String version = driver.getClass().getPackage().getImplementationVersion();
        check(version != null, "driver-version-available");
        System.out.printf("version %s %s Java %s%n", driver.getClass().getName(), version,
                          Runtime.version());

        rejectConnection(mysql, "wrong-password", BRANCH, true, "FG-1002", "wrong-password");
        rejectConnection(mysql, PASSWORD, "other-branch", true, "FG-2003", "unauthorized-branch");
        rejectConnection(mysql, PASSWORD, BRANCH, false, "certificate", "wrong-ca");
        if (mysql) {
            rejectConnection(true, PASSWORD, "", true, "FG-2003", "missing-branch");
        }
        try (Connection connection = connect(mysql, PASSWORD, BRANCH, true)) {
            check(singleInt(connection, "SELECT 1") == 1, "verified-tls-and-select");
            try (Statement statement = connection.createStatement()) {
                reject(() -> statement.execute("DROP TABLE fixture_items"), "FG-2002", "unsupported-sql");
            }
            prepared(connection);
            try (Statement statement = connection.createStatement()) {
                statement.execute(mysql ? "START TRANSACTION" : "BEGIN");
                statement.execute(INSERT_EVENT);
            }
            check(singleInt(connection, COUNT_EVENTS) == 1, "transaction-visibility");
        }
        try (Connection connection = connect(mysql, PASSWORD, BRANCH, true)) {
            check(singleInt(connection, COUNT_EVENTS) == 0, "disconnect-rollback");
        }
    }

    private static String url(boolean mysql, String database) {
        return (mysql ? "jdbc:mysql://localhost:13306/" : "jdbc:postgresql://localhost:15432/") + database;
    }

    private static Connection connect(boolean mysql, String password, String database, boolean trusted)
            throws SQLException {
        Properties options = new Properties();
        options.setProperty("user", USER);
        options.setProperty("password", password);
        if (mysql) {
            options.setProperty("sslMode", "VERIFY_IDENTITY");
            options.setProperty("trustCertificateKeyStoreUrl", trusted ? "file:/tmp/frontend.p12" : "file:/tmp/backend.p12");
            options.setProperty("trustCertificateKeyStoreType", "PKCS12");
            options.setProperty("trustCertificateKeyStorePassword", PASSWORD);
            options.setProperty("useServerPrepStmts", "true");
            options.setProperty("allowPublicKeyRetrieval", "false");
            options.setProperty("connectTimeout", "5000");
            options.setProperty("socketTimeout", "5000");
        } else {
            options.setProperty("sslmode", "verify-full");
            options.setProperty("sslrootcert", trusted ? "/p1-tls/frontend-ca.pem" : "/p1-tls/backend-ca.pem");
            options.setProperty("gssEncMode", "disable");
            options.setProperty("assumeMinServerVersion", "16");
            options.setProperty("prepareThreshold", "1");
            options.setProperty("connectTimeout", "5");
            options.setProperty("socketTimeout", "5");
        }
        return DriverManager.getConnection(url(mysql, database), options);
    }

    private static void rejectConnection(boolean mysql, String password, String database, boolean trusted,
                                         String marker, String name) throws Exception {
        reject(() -> {
            try (Connection ignored = connect(mysql, password, database, trusted)) {
                // Reaching this scope means the fixture admitted the rejected connection.
            }
        }, marker, name);
    }

    private static int singleInt(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            if (!rows.next()) {
                throw new AssertionError("No row returned");
            }
            int value = rows.getInt(1);
            if (rows.next()) {
                throw new AssertionError("Extra row returned");
            }
            return value;
        }
    }

    private static void prepared(Connection connection) throws Exception {
        byte[][] expected = {null, {}, {0, (byte) 255, 65}};
        try (PreparedStatement statement = connection.prepareStatement(SELECT_ITEM)) {
            for (int index = 0; index < expected.length; index++) {
                statement.setInt(1, index + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    check(rows.next() && rows.getInt("id") == index + 1
                          && Arrays.equals(rows.getBytes("payload"), expected[index]) && !rows.next(),
                          "prepared-reuse-" + (index + 1));
                }
            }
            statement.clearParameters();
            reject(statement::executeQuery, "parameter", "incorrect-binding");
        }
    }

    private static void check(boolean condition, String name) {
        if (!condition) {
            throw new AssertionError(name);
        }
        System.out.printf("case %s PASS%n", name);
    }

    private static void reject(SqlOperation operation, String marker, String name) throws Exception {
        try {
            operation.run();
        } catch (SQLException error) {
            String expected = marker.toLowerCase(Locale.ROOT);
            for (Throwable cause = error; cause != null; cause = cause.getCause()) {
                String message = cause.getMessage();
                if (message != null && message.toLowerCase(Locale.ROOT).contains(expected)) {
                    check(true, name);
                    return;
                }
            }
            throw error;
        }
        throw new AssertionError(name + " unexpectedly succeeded");
    }

    @FunctionalInterface
    private interface SqlOperation {
        void run() throws Exception;
    }
}
