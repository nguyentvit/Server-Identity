#!/bin/bash

# Khởi động SQL Server trong background
/opt/mssql/bin/sqlservr &

# Đợi cho SQL Server sẵn sàng
echo "Waiting for SQL Server to be available..."
attempts=0
max_attempts=50
until /opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P "$SA_PASSWORD" -Q "SELECT 1" > /dev/null 2>&1; do
  attempts=$((attempts+1))
  if [ $attempts -ge $max_attempts ]; then
    echo "SQL Server is taking too long to start. Exiting..."
    exit 1
  fi
  echo "SQL Server is not yet available, retrying... Attempt: $attempts"
  sleep 10
done

echo "SQL Server is now available. Running the init script..."

# Chạy script SQL để tạo bảng
/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P "$SA_PASSWORD" -i /usr/src/app/CreateTables.sql

echo "Initialization complete. SQL Server is ready."

# Giữ container chạy
wait
