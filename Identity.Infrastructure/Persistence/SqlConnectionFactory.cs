using Identity.Application.Data;
using System.Data.SqlClient;
using System.Data;

namespace Identity.Infrastructure.Persistence
{
    public class SqlConnectionFactory : ISqlConnectionFactory, IDisposable
    {
        private readonly string _connectionString;
        private IDbConnection _connection;
        private bool _disposed;

        public SqlConnectionFactory(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        }

        public IDbConnection GetOpenConnection()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SqlConnectionFactory));

            if (_connection == null || _connection.State != ConnectionState.Open)
            {
                _connection = new SqlConnection(_connectionString);
                _connection.Open();
            }

            return _connection;
        }

        public void Dispose()
        {
            if (_disposed) return;

            if (_connection != null && _connection.State == ConnectionState.Open)
            {
                _connection.Dispose();
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
