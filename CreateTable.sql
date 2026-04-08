-- CUSTOMER
CREATE TABLE customer (
    customer_id SERIAL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    phone VARCHAR(20),
    date_of_birth DATE,
    address TEXT
);

-- ACCOUNT
CREATE TABLE account (
    account_id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customer(customer_id),
    account_type VARCHAR(50),
    balance DECIMAL(10,2),
    created_at TIMESTAMP,
    status VARCHAR(20)
);

-- CREDIT CARD
CREATE TABLE credit_card (
    card_id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES account(account_id),
    card_number VARCHAR(20) UNIQUE,
    expiration_date DATE,
    cvv VARCHAR(4),
    card_status VARCHAR(20)
);

-- MERCHANT
CREATE TABLE merchant (
    merchant_id SERIAL PRIMARY KEY,
    merchant_name VARCHAR(100),
    category VARCHAR(50),
    merchant_location TEXT
);

-- DEVICE
CREATE TABLE device (
    device_id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customer(customer_id),
    device_type VARCHAR(50),
    device_fingerprint TEXT,
    first_registered_date TIMESTAMP,
    device_status VARCHAR(20)
);

-- TRANSACTION
CREATE TABLE transaction (
    transaction_id SERIAL PRIMARY KEY,
    card_id INTEGER REFERENCES credit_card(card_id),
    merchant_id INTEGER REFERENCES merchant(merchant_id),
    device_id INTEGER REFERENCES device(device_id),
    transaction_amount DECIMAL(10,2),
    transaction_date TIMESTAMP,
    transaction_location TEXT,
    transaction_status VARCHAR(20)
);

-- FRAUD ALERT
CREATE TABLE fraud_alert (
    alert_id SERIAL PRIMARY KEY,
    transaction_id INTEGER REFERENCES transaction(transaction_id),
    alert_reason TEXT,
    alert_date TIMESTAMP,
    alert_status VARCHAR(20)
);

-- FRAUD REPORT
CREATE TABLE fraud_report (
    report_id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customer(customer_id),
    transaction_id INTEGER REFERENCES transaction(transaction_id),
    report_date TIMESTAMP,
    resolution_status VARCHAR(20)
);

-- CREDIT HISTORY
CREATE TABLE credit_history (
    credit_history_id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customer(customer_id),
    credit_score INTEGER,
    total_credit_limit DECIMAL(10,2),
    total_outstanding_balance DECIMAL(10,2),
    last_updated TIMESTAMP
);

-- AUTHORIZED USER
CREATE TABLE authorized_user (
    authorized_user_id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES account(account_id),
    name VARCHAR(100),
    relationship_type VARCHAR(50),
    date_added TIMESTAMP
);
