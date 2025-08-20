using LiteDB;
using MongoDB.Driver;
using System.Linq.Expressions;
using System.Reflection;

namespace SwarmUI.Utils;

/// <summary>Represents a generic collection of data items.</summary>
public interface IDataCollection<T>
{
    void Upsert(T item);
    void Upsert(string id, T item);
    T FindById(string id);
    IEnumerable<T> Find(Expression<Func<T, bool>> predicate);
    IEnumerable<T> FindAll();
    int DeleteMany(Expression<Func<T, bool>> predicate);
    bool Delete(string id);
}

/// <summary>Represents a generic database.</summary>
public interface IDataDatabase : IDisposable
{
    IDataCollection<T> GetCollection<T>(string name);
}

/// <summary>LiteDB implementation of <see cref="IDataDatabase"/>.</summary>
public class LiteDbDatabase : IDataDatabase
{
    private readonly LiteDatabase _db;

    public LiteDbDatabase(string path)
    {
        _db = new LiteDatabase(path);
    }

    public IDataCollection<T> GetCollection<T>(string name)
    {
        return new LiteDbCollection<T>(_db.GetCollection<T>(name));
    }

    public void Dispose()
    {
        _db.Dispose();
        GC.SuppressFinalize(this);
    }

    private class LiteDbCollection<T> : IDataCollection<T>
    {
        private readonly ILiteCollection<T> _col;

        public LiteDbCollection(ILiteCollection<T> col)
        {
            _col = col;
        }

        public void Upsert(T item) => _col.Upsert(item);

        public void Upsert(string id, T item) => _col.Upsert(id, item);

        public T FindById(string id) => _col.FindById(id);

        public IEnumerable<T> Find(Expression<Func<T, bool>> predicate) => _col.Find(predicate);

        public IEnumerable<T> FindAll() => _col.FindAll();

        public int DeleteMany(Expression<Func<T, bool>> predicate) => _col.DeleteMany(predicate);

        public bool Delete(string id) => _col.Delete(id);
    }
}

/// <summary>MongoDB implementation of <see cref="IDataDatabase"/>.</summary>
public class MongoDbDatabase : IDataDatabase
{
    private readonly IMongoDatabase _db;

    public MongoDbDatabase(string connectionString, string databaseName)
    {
        MongoClient client = new(connectionString);
        _db = client.GetDatabase(databaseName);
    }

    public IDataCollection<T> GetCollection<T>(string name)
    {
        return new MongoDbCollection<T>(_db.GetCollection<T>(name));
    }

    public void Dispose()
    {
        // MongoDB driver manages connections internally; nothing to dispose.
    }

    private class MongoDbCollection<T> : IDataCollection<T>
    {
        private readonly IMongoCollection<T> _col;
        private static readonly PropertyInfo IDProp = typeof(T).GetProperty("ID");

        public MongoDbCollection(IMongoCollection<T> col)
        {
            _col = col;
        }

        public void Upsert(T item)
        {
            if (IDProp is null)
            {
                _col.InsertOne(item);
                return;
            }
            object id = IDProp.GetValue(item);
            Upsert(id?.ToString(), item);
        }

        public void Upsert(string id, T item)
        {
            var filter = Builders<T>.Filter.Eq("_id", id);
            _col.ReplaceOne(filter, item, new ReplaceOptions { IsUpsert = true });
        }

        public T FindById(string id)
        {
            var filter = Builders<T>.Filter.Eq("_id", id);
            return _col.Find(filter).FirstOrDefault();
        }

        public IEnumerable<T> Find(Expression<Func<T, bool>> predicate)
        {
            return _col.Find(predicate).ToEnumerable();
        }

        public IEnumerable<T> FindAll()
        {
            return _col.Find(Builders<T>.Filter.Empty).ToEnumerable();
        }

        public int DeleteMany(Expression<Func<T, bool>> predicate)
        {
            return (int)_col.DeleteMany(predicate).DeletedCount;
        }

        public bool Delete(string id)
        {
            var filter = Builders<T>.Filter.Eq("_id", id);
            return _col.DeleteOne(filter).DeletedCount > 0;
        }
    }
}
