-- Shared deterministic fixture for the smoke corpus.
-- Applied identically to the reference and candidate sides of every case.
CREATE TABLE orders (
    tenant_id BIGINT NOT NULL,
    id BIGINT NOT NULL,
    amount DECIMAL(12, 2),
    note VARCHAR(64),
    PRIMARY KEY (tenant_id, id)
);
INSERT INTO orders (tenant_id, id, amount, note) VALUES
    (1, 1, 10.00, 'alpha'),
    (1, 2, 20.00, 'bravo'),
    (1, 3, 30.00, 'charlie'),
    (2, 2, 40.00, 'bravo-tenant-two'),
    (1, 5, 50.00, 'echo'),
    (1, 6, 10.00, 'alpha-dup-amount');
