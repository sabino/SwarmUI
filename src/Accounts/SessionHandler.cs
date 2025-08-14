using SwarmUI.Utils;
using SwarmUI.Core;
using System;
using System.Collections.Concurrent;
using LiteDB;
using MongoDB.Driver;
using SwarmUI.Text2Image;
using FreneticUtilities.FreneticToolkit;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticDataSyntax;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace SwarmUI.Accounts;

/// <summary>Core manager for sessions.</summary>
public class SessionHandler
{
    /// <summary>How long the random session ID tokens should be.</summary>
    public int SessionIDLength = 40; // TODO: Configurable

    /// <summary>How long to store sessions for before considering inactive and deleting.</summary>
    public TimeSpan MaxSessionAge = TimeSpan.FromDays(31); // TODO: Configurable

    /// <summary>Map of currently tracked sessions by ID.</summary>
    public ConcurrentDictionary<string, Session> Sessions = new();

    /// <summary>Temporary map of current users. Do not use this directly, use <see cref="GetUser(string)"/>.</summary>
    public ConcurrentDictionary<string, User> Users = new();

    /// <summary>Map of user roles by ID.</summary>
    public ConcurrentDictionary<string, Role> Roles = new();

    /// <summary>Set of permission nodes that this server is familiar with. May expand upon updates, extension loads, etc.</summary>
    public HashSet<string> TrackedPermissions = [];

    /// <summary>ID to use for the local user when in single-user mode.</summary>
    public static string LocalUserID = "local";

    /// <summary>Internal LiteDB database.</summary>
    public ILiteDatabase Database;

    /// <summary>LiteDB collections.</summary>
    public ILiteCollection<User.DatabaseEntry> UserDatabase;
    public ILiteCollection<Session.DatabaseEntry> SessionDatabase;
    public ILiteCollection<T2IPreset> T2IPresets;
    public ILiteCollection<GenericDataStore> GenericData;
    public ILiteCollection<LoginSession> LoginSessions;

    /// <summary>MongoDB usage flag and collections.</summary>
    public bool UseMongo;
    public MongoClient Mongo;
    public IMongoDatabase MongoDatabase;
    public IMongoCollection<User.DatabaseEntry> MongoUsers;
    public IMongoCollection<Session.DatabaseEntry> MongoSessions;
    public IMongoCollection<T2IPreset> MongoT2IPresets;
    public IMongoCollection<GenericDataStore> MongoGenericData;
    public IMongoCollection<LoginSession> MongoLoginSessions;

    /// <summary>Internal database access locker.</summary>
    public LockObject DBLock = new();

    public User GenericSharedUser;

    /// <summary>Saves persistent data to file.</summary>
    public void Save()
    {
        lock (DBLock)
        {
            FDSSection roleSection = new();
            foreach (Role role in Roles.Values)
            {
                roleSection.SetRoot(role.ID, role.Data.Save(true));
            }
            roleSection.SetRoot("___$tracked", TrackedPermissions);
            roleSection.SaveToFile($"{Program.DataDir}/Roles.fds");
        }
    }

    /// <summary>Keeps the default permission list applied.</summary>
    public void ApplyDefaultPermissions()
    {
        bool any = false;
        foreach (PermInfo perm in Permissions.Registered.Values)
        {
            if (!TrackedPermissions.Contains(perm.ID))
            {
                any = true;
                TrackedPermissions.Add(perm.ID);
                if (perm.Default == PermissionDefault.NOBODY)
                {
                    Roles["owner"].Data.PermissionFlags.Add(perm.ID);
                }
                else if (perm.Default == PermissionDefault.ADMINS)
                {
                    Roles["owner"].Data.PermissionFlags.Add(perm.ID);
                    Roles["admin"].Data.PermissionFlags.Add(perm.ID);
                }
                else if (perm.Default == PermissionDefault.POWERUSERS)
                {
                    Roles["owner"].Data.PermissionFlags.Add(perm.ID);
                    Roles["admin"].Data.PermissionFlags.Add(perm.ID);
                    Roles["poweruser"].Data.PermissionFlags.Add(perm.ID);
                }
                else if (perm.Default == PermissionDefault.USER)
                {
                    Roles["owner"].Data.PermissionFlags.Add(perm.ID);
                    Roles["admin"].Data.PermissionFlags.Add(perm.ID);
                    Roles["poweruser"].Data.PermissionFlags.Add(perm.ID);
                    Roles["user"].Data.PermissionFlags.Add(perm.ID);
                }
                else if (perm.Default == PermissionDefault.GUEST)
                {
                    Roles["owner"].Data.PermissionFlags.Add(perm.ID);
                    Roles["admin"].Data.PermissionFlags.Add(perm.ID);
                    Roles["poweruser"].Data.PermissionFlags.Add(perm.ID);
                    Roles["user"].Data.PermissionFlags.Add(perm.ID);
                    Roles["guest"].Data.PermissionFlags.Add(perm.ID);
                }
            }
        }
        if (any)
        {
            Save();
        }
    }

    /// <summary>Helper for the database to store generic datablobs.</summary>
    public class GenericDataStore
    {
        [BsonId]
        [MongoDB.Bson.Serialization.Attributes.BsonId]
        public string ID { get; set; }

        public string Data { get; set; }
    }

    public static int PatchOwnerMaxT2I = 32, PatchOwnerMaxDepth = 5;
    public static bool PatchOwnerAllowUnsafe = false;

    /// <summary>Helper for login session data.</summary>
    public class LoginSession
    {
        [BsonId]
        [MongoDB.Bson.Serialization.Attributes.BsonId]
        public string ID { get; set; }

        public string UserID { get; set; }

        public string OriginAddress { get; set; }

        public string OriginUserAgent { get; set; }

        public long LastActiveUnixTime { get; set; }

        public string ValidationHash { get; set; }

        public bool CheckValidation(string input)
        {
            (string salt, string content) = ValidationHash.BeforeAndAfter(':');
            byte[] saltBytes = Convert.FromHexString(salt);
            byte[] contentBytes = Convert.FromHexString(content);
            byte[] inHash = KeyDerivation.Pbkdf2(password: input, salt: saltBytes, prf: KeyDerivationPrf.HMACSHA256, iterationCount: 10, numBytesRequested: 256 / 8);
            return inHash.SequenceEqual(contentBytes);
        }
    }

    public SessionHandler()
    {
        UseMongo = string.Equals(Environment.GetEnvironmentVariable("SWARM_DB"), "mongodb", StringComparison.OrdinalIgnoreCase);
        if (UseMongo)
        {
            string conn = Environment.GetEnvironmentVariable("SWARM_MONGO_CONNECTION") ?? "mongodb://localhost:27017";
            string dbName = Environment.GetEnvironmentVariable("SWARM_MONGO_DB") ?? "swarmui";
            Mongo = new MongoClient(conn);
            MongoDatabase = Mongo.GetDatabase(dbName);
            MongoUsers = MongoDatabase.GetCollection<User.DatabaseEntry>("users");
            MongoSessions = MongoDatabase.GetCollection<Session.DatabaseEntry>("sessions");
            MongoT2IPresets = MongoDatabase.GetCollection<T2IPreset>("t2i_presets");
            MongoGenericData = MongoDatabase.GetCollection<GenericDataStore>("generic_data");
            MongoLoginSessions = MongoDatabase.GetCollection<LoginSession>("login_sessions");
        }
        else
        {
            Database = new LiteDatabase($"{Program.DataDir}/Users.ldb");
            UserDatabase = Database.GetCollection<User.DatabaseEntry>("users");
            SessionDatabase = Database.GetCollection<Session.DatabaseEntry>("sessions");
            T2IPresets = Database.GetCollection<T2IPreset>("t2i_presets");
            GenericData = Database.GetCollection<GenericDataStore>("generic_data");
            LoginSessions = Database.GetCollection<LoginSession>("login_sessions");
        }
        FDSSection rolesData = new();
        try
        {
            rolesData = FDSUtility.ReadFile($"{Program.DataDir}/Roles.fds");
        }
        catch (Exception) { }
        foreach (string id in rolesData.GetRootKeys())
        {
            if (id.StartsWith("___$"))
            {
                continue;
            }
            FDSSection data = rolesData.GetSection(id);
            if (data is null)
            {
                Logs.Error($"Failed to load role {id} from Roles.fds");
                continue;
            }
            Roles[id] = new Role(id);
            Roles[id].Data.Load(data);
        }
        TrackedPermissions = [.. (rolesData.GetRootData("___$tracked") ?? new(new List<FDSData>())).AsStringList];
        if (!Roles.ContainsKey("owner"))
        {
            Role r = new("owner") { IsAutoGenerated = true };
            Roles["owner"] = r;
            r.Data.Name = "Owner";
            r.Data.Description = "(Auto Generated Role, cannot delete). The owner of the server, local user when account system is disabled. Generally should have all permissions ever always.";
            r.Data.MaxT2ISimultaneous = PatchOwnerMaxT2I;
            r.Data.MaxOutPathDepth = PatchOwnerMaxDepth;
            r.Data.AllowUnsafeOutpaths = PatchOwnerAllowUnsafe;
        }
        if (!Roles.ContainsKey("admin"))
        {
            Role r = new("admin") { IsAutoGenerated = true };
            Roles["admin"] = r;
            r.Data.Name = "Admin";
            r.Data.Description = "(Auto Generated Role, cannot delete). An administrator of the server, has near-total control.";
        }
        if (!Roles.ContainsKey("poweruser"))
        {
            Role r = new("poweruser") { IsAutoGenerated = true };
            Roles["poweruser"] = r;
            r.Data.Name = "PowerUser";
            r.Data.Description = "(Auto Generated Role, cannot delete). A very advanced, and trusted, user. Has access to things that could be dangerous or can be maliciously abused.";
        }
        if (!Roles.ContainsKey("user"))
        {
            Role r = new("user") { IsAutoGenerated = true };
            Roles["user"] = r;
            r.Data.Name = "User";
            r.Data.Description = "(Auto Generated Role, cannot delete). A general user. The default role for valid accounts.";
        }
        if (!Roles.ContainsKey("guest"))
        {
            Role r = new("guest") { IsAutoGenerated = true };
            Roles["guest"] = r;
            r.Data.Name = "Guest";
            r.Data.Description = "(Auto Generated Role, cannot delete). An unregistered or unverified guest account. Only when public unverified access is enabled.";
        }
        bool fixCurse = Roles["guest"].Data.PermissionFlags.Contains("*"); // Patch for prerel default * to everyone.
        foreach (string roleId in new string[] { "guest", "user", "poweruser", "admin", "owner" })
        {
            if (fixCurse)
            {
                Roles[roleId].Data.PermissionFlags.Remove("*");
            }
            Roles[roleId].IsAutoGenerated = true;
        }
        Roles["owner"].Data.PermissionFlags.Add("*");
        ApplyDefaultPermissions();
        GenericSharedUser = GetUser("__shared");
        Utilities.RunCheckedTask(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10), Program.GlobalProgramCancel);
            CleanOldSessions();
        });
    }

    public User.DatabaseEntry FindUserEntry(string id) => UseMongo ? MongoUsers.Find(u => u.ID == id).FirstOrDefault() : UserDatabase.FindById(id);

    public void UpsertUser(User.DatabaseEntry user)
    {
        if (UseMongo) { MongoUsers.ReplaceOne(u => u.ID == user.ID, user, new ReplaceOptions { IsUpsert = true }); }
        else { UserDatabase.Upsert(user); }
    }

    public bool DeleteUser(string id) => UseMongo ? MongoUsers.DeleteOne(u => u.ID == id).DeletedCount > 0 : UserDatabase.Delete(id);

    public IEnumerable<Session.DatabaseEntry> GetAllSessions() => UseMongo ? MongoSessions.Find(_ => true).ToEnumerable() : SessionDatabase.FindAll();

    public Session.DatabaseEntry FindSessionEntry(string id) => UseMongo ? MongoSessions.Find(s => s.ID == id).FirstOrDefault() : SessionDatabase.FindById(id);

    public void UpsertSession(Session.DatabaseEntry sess)
    {
        if (UseMongo) { MongoSessions.ReplaceOne(s => s.ID == sess.ID, sess, new ReplaceOptions { IsUpsert = true }); }
        else { SessionDatabase.Upsert(sess); }
    }

    public bool DeleteSession(string id) => UseMongo ? MongoSessions.DeleteOne(s => s.ID == id).DeletedCount > 0 : SessionDatabase.Delete(id);

    public T2IPreset FindPreset(string id) => UseMongo ? MongoT2IPresets.Find(p => p.ID == id).FirstOrDefault() : T2IPresets.FindById(id);

    public void UpsertPreset(T2IPreset preset)
    {
        if (UseMongo) { MongoT2IPresets.ReplaceOne(p => p.ID == preset.ID, preset, new ReplaceOptions { IsUpsert = true }); }
        else { T2IPresets.Upsert(preset.ID, preset); }
    }

    public bool DeletePreset(string id) => UseMongo ? MongoT2IPresets.DeleteOne(p => p.ID == id).DeletedCount > 0 : T2IPresets.Delete(id);

    public void DeletePresetsByPrefix(string prefix)
    {
        if (UseMongo) { MongoT2IPresets.DeleteMany(p => p.ID.StartsWith(prefix)); }
        else { T2IPresets.DeleteMany(b => b.ID.StartsWith(prefix)); }
    }

    public GenericDataStore FindGenericData(string id) => UseMongo ? MongoGenericData.Find(g => g.ID == id).FirstOrDefault() : GenericData.FindById(id);

    public List<GenericDataStore> FindGenericDataByPrefix(string prefix) => UseMongo ? MongoGenericData.Find(g => g.ID.StartsWith(prefix)).ToList() : [.. GenericData.Find(g => g.ID.StartsWith(prefix))];

    public void UpsertGenericData(GenericDataStore data)
    {
        if (UseMongo) { MongoGenericData.ReplaceOne(g => g.ID == data.ID, data, new ReplaceOptions { IsUpsert = true }); }
        else { GenericData.Upsert(data.ID, data); }
    }

    public bool DeleteGenericData(string id) => UseMongo ? MongoGenericData.DeleteOne(g => g.ID == id).DeletedCount > 0 : GenericData.Delete(id);

    public void DeleteGenericDataByPrefix(string prefix)
    {
        if (UseMongo) { MongoGenericData.DeleteMany(g => g.ID.StartsWith(prefix)); }
        else { GenericData.DeleteMany(b => b.ID.StartsWith(prefix)); }
    }

    public LoginSession FindLoginSession(string id) => UseMongo ? MongoLoginSessions.Find(l => l.ID == id).FirstOrDefault() : LoginSessions.FindById(id);

    public void UpsertLoginSession(LoginSession session)
    {
        if (UseMongo) { MongoLoginSessions.ReplaceOne(l => l.ID == session.ID, session, new ReplaceOptions { IsUpsert = true }); }
        else { LoginSessions.Upsert(session.ID, session); }
    }

    public bool DeleteLoginSession(string id) => UseMongo ? MongoLoginSessions.DeleteOne(l => l.ID == id).DeletedCount > 0 : LoginSessions.Delete(id);

    public void CleanOldSessions()
    {
        long cutOffTimeUTC = DateTimeOffset.UtcNow.Subtract(MaxSessionAge).ToUnixTimeSeconds();
        lock (DBLock)
        {
            foreach (Session.DatabaseEntry sess in GetAllSessions())
            {
                if (sess.LastActiveUnixTime < cutOffTimeUTC)
                {
                    DeleteSession(sess.ID);
                }
            }
        }
    }

    public Session CreateSession(string source, string userId = null)
    {
        if (HasShutdown)
        {
            throw new SwarmReadableErrorException("Session handler is shutting down.");
        }
        userId ??= LocalUserID;
        User user = GetUser(userId);
        if (!user.MayCreateSessions)
        {
            throw new SwarmReadableErrorException($"User '{user.UserID}' may not create new sessions currently.");
        }
        Logs.Info($"Creating new session '{user.UserID}' for {source}");
        for (int i = 0; i < 1000; i++)
        {
            Session sess = new()
            {
                ID = Utilities.SecureRandomHex(SessionIDLength),
                OriginAddress = source,
                User = user
            };
            if (Sessions.TryAdd(sess.ID, sess))
            {
                sess.User.CurrentSessions[sess.ID] = sess;
                lock (DBLock)
                {
                    UpsertSession(sess.MakeDBEntry());
                }
                return sess;
            }
        }
        throw new SwarmReadableErrorException("Something is critically wrong in the session handler, cannot generate unique IDs!");
    }

    /// <summary>Cancel, remove, and destroy a session entirely.</summary>
    public void RemoveSession(Session session)
    {
        try
        {
            session.SessInterrupt.Cancel();
        }
        catch (Exception) { }
        Sessions.TryRemove(session.ID, out _);
        session.User.CurrentSessions.TryRemove(session.ID, out _);
        lock (DBLock)
        {
            DeleteSession(session.ID);
        }
    }

    /// <summary>Gets or creates the user for the given ID.</summary>
    public User GetUser(string userId, bool makeNew = true)
    {
        userId = Utilities.StrictFilenameClean(userId).Replace("/", "");
        if (userId.Length == 0)
        {
            userId = "_";
        }
        if (Users.TryGetValue(userId, out User user))
        {
            return user;
        }
        lock (DBLock)
        {
            if (!makeNew)
            {
                User.DatabaseEntry userData = FindUserEntry(userId);
                if (userData is null)
                {
                    return null;
                }
                return Users.GetOrAdd(userId, _ => new(this, userData));
            }
            return Users.GetOrAdd(userId, _ => // Intentional GetOrAdd due to special locking requirements (DBLock)
            {
                User.DatabaseEntry userData = FindUserEntry(userId);
                userData ??= new() { ID = userId, RawSettings = "\n" };
                return new(this, userData);
            });
        }
    }

    /// <summary>Tries to get the session for an id.</summary>
    /// <returns><see cref="true"/> if found, otherwise <see cref="false"/>.</returns>
    public bool TryGetSession(string id, out Session session)
    {
        if (Sessions.TryGetValue(id, out session))
        {
            return true;
        }
        lock (DBLock)
        {
            if (Sessions.TryGetValue(id, out session)) // double-check inside lock
            {
                return true;
            }
            Session.DatabaseEntry existing = FindSessionEntry(id);
            if (existing is not null)
            {
                if (!string.IsNullOrWhiteSpace(existing.OriginToken))
                {
                    if (FindLoginSession(existing.OriginToken) is null)
                    {
                        DeleteSession(id);
                        return false;
                    }
                }
                session = new()
                {
                    ID = existing.ID,
                    OriginAddress = existing.OriginAddress,
                    OriginToken = existing.OriginToken,
                    User = GetUser(existing.UserID)
                };
                if (Sessions.TryAdd(session.ID, session))
                {
                    session.User.CurrentSessions[session.ID] = session;
                    UpsertSession(session.MakeDBEntry());
                    return true;
                }
            }
        }
        session = null;
        return false;
    }

    /// <summary>Remove all data associated with a given user from the user databases. Does not remove output history or anything they did outside of their personal user data.</summary>
    public void RemoveUser(User user)
    {
        lock (DBLock)
        {
            string prefix = $"{user.UserID}///";
            user.MayCreateSessions = false;
            foreach (Session userSess in user.CurrentSessions.Values.ToArray())
            {
                RemoveSession(userSess);
            }
            DeletePresetsByPrefix(prefix);
            DeleteGenericDataByPrefix(prefix);
            DeleteUser(user.UserID);
            Users.TryRemove(user.UserID, out _);
        }
    }

    private volatile bool HasShutdown;

    /// <summary>Main shutdown handler, triggered by <see cref="Program.Shutdown"/>.</summary>
    public void Shutdown()
    {
        if (HasShutdown)
        {
            return;
        }
        HasShutdown = true;
        Logs.Info("Will shut down session handler...");
        lock (DBLock)
        {
            Save();
            Sessions.Clear();
            Logs.Info("Will save user data.");
            Database.Dispose();
        }
        Logs.Info("Session handler is shut down.");
    }
}
