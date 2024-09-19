IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'IdentityDb')
BEGIN
    PRINT 'Creating IdentityDb database...';
    CREATE DATABASE IdentityDb;
END
ELSE
BEGIN
    PRINT 'Database IdentityDb already exists.';
END
