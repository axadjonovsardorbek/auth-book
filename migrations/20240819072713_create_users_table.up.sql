DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'role_enum') THEN
        CREATE TYPE role_enum AS ENUM ('admin', 'user', 'publisher', 'shop', 'super_admin');
    END IF;
EXCEPTION
    WHEN duplicate_object THEN null;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'super_admin' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'role_enum')) THEN
        ALTER TYPE role_enum ADD VALUE 'super_admin';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    phone_number VARCHAR(13),
    date_of_birth DATE,
    role role_enum,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at BIGINT DEFAULT 0
);

CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    phone_number VARCHAR(13),
    password VARCHAR(256),
    date_of_birth DATE,
    role role_enum,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS publishers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(15) NOT NULL,
    -- cities_id UUID REFERENCES cities(id),
    -- district_id UUID REFERENCES districts(id),
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    img_url VARCHAR,
    role role_enum NOT NULL DEFAULT 'publisher',
    status BOOLEAN DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at BIGINT DEFAULT 0,
    UNIQUE(username, deleted_at),
    UNIQUE(email, deleted_at),
    UNIQUE(phone_number, deleted_at)
);



CREATE TRIGGER update_admins_updated_at
BEFORE UPDATE ON admins
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();



INSERT INTO admins (id, first_name, last_name, email, phone_number, password, date_of_birth, role, created_at, updated_at, deleted_at)
VALUES
    ('f3b1e5c0-3e6f-11ed-b878-0242ac120002', 'Sardorbek', 'Axadjonov', 'axadjonovsardorbeck@gmail.com', '+998200070424', '$2a$10$DCHM3DqLWoA.lgdqM7Tkk.Qdq/OHMkBq5DaM6TCYpQQKmdF7tmfQW', '2007-04-24', 'super_admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0);
