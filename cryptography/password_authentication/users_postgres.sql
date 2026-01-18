-- PostgreSQL Database Dump
-- Generated with passlib (professional password hashing)

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    allowed_files TEXT NOT NULL
);

-- Clear existing data
TRUNCATE TABLE users RESTART IDENTITY CASCADE;

-- Insert test users
INSERT INTO users (username, password_hash, allowed_files) VALUES
    ('alice_scrypt', '$scrypt$ln=17,r=8,p=1$X8vZ+//f+x/j3HuvVYqxtg$zr02bz5Uh9Gl05gTD4lKDc7MDbJRPgdW5xNAPQk//e4', 'documents/file1.txt,file2.txt');
INSERT INTO users (username, password_hash, allowed_files) VALUES
    ('bob_pbkdf2', '$pbkdf2-sha256$600000$OedcixFijLFWCkHI.T9njA$kHN6UOUuUbcAkk3LBPb2LPvAGzTyb4eA5QPBOwmWrYk', 'reports/report1.pdf,report2.pdf');
INSERT INTO users (username, password_hash, allowed_files) VALUES
    ('charlie_argon2', '$argon2id$v=19$m=19456,t=2,p=1$XYtRau1da43xHgMghHAuhQ$apMn1wIYNh4eeHwmoqVltCEZCfKOPf5VIXmyUCZLheM', 'data/data1.csv,data2.csv');
INSERT INTO users (username, password_hash, allowed_files) VALUES
    ('dave_bcrypt', '$2b$12$rhJ494Vhn2SB6n6OuAQbP.FNSJWy1GYABqV4lMN4mGBmtjvjEPziu', 'logs/access.log,error.log');
INSERT INTO users (username, password_hash, allowed_files) VALUES
    ('eve_scrypt', '$scrypt$ln=17,r=8,p=1$q/X+f6+VshYCgJBSKiWEcA$RWTb0j5g/f72NK2xXLOcSbbKZ0bnIDMRyWZWKPGl3LY', 'admin/config.json');

-- Verify data
SELECT username, LEFT(password_hash, 50) as hash_preview, allowed_files FROM users;
