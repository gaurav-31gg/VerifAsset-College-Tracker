/*
 * VerifAsset - College Asset Tracker Backend (v2.0)
 * FINAL LOGIC FIX:
 * This version COMPLETELY fixes the Merkle root bug by correcting
 * the core blockchain logic for finalization.
 *
 * === SETUP ===
 * 1. Place sqlite3.c and sqlite3.h in this folder.
 *
 * === COMPILE COMMAND (Two Steps) ===
 * 1. g++ -c -x c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_DATETIME_FUNCS
 * 2. g++ -std=c++17 -fpermissive main.cpp sqlite3.o -o server.exe -lws2_32
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <chrono>
#include <cmath>
#include <atomic>
#include <map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "sqlite3.h" // The SQLite header

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// --- Global Handles ---
sqlite3 *db;
atomic<bool> server_running(true);

// ------------------ SHA256 ------------------
class SHA256
{
    static const uint32_t k[64];
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

public:
    static string hash(const string &input);
};
string SHA256::hash(const string &input)
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    vector<uint8_t> bytes(input.begin(), input.end());
    uint64_t bit_len = bytes.size() * 8;
    bytes.push_back(0x80);
    while ((bytes.size() * 8) % 512 != 448)
        bytes.push_back(0);
    for (int i = 7; i >= 0; --i)
        bytes.push_back((bit_len >> (i * 8)) & 0xFF);
    for (size_t chunk = 0; chunk < bytes.size(); chunk += 64)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (bytes[chunk + 4 * i] << 24) | (bytes[chunk + 4 * i + 1] << 16) | (bytes[chunk + 4 * i + 2] << 8) | (bytes[chunk + 4 * i + 3]);
        for (int i = 16; i < 64; i++)
        {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], h0 = h[7];
        for (int i = 0; i < 64; i++)
        {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h0 + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h0 = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h0;
    }
    ostringstream oss;
    for (int i = 0; i < 8; i++)
        oss << hex << setfill('0') << setw(8) << h[i];
    return oss.str();
}
const uint32_t SHA256::k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1B2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24c8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
string sha256_hex(const string &s) { return SHA256::hash(s); }

// ------------------ Helpers ------------------
string json_escape(const string &s)
{
    string out;
    for (char c : s)
    {
        if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else
            out += c;
    }
    return out;
}

string url_decode(const string &value)
{
    string result;
    result.reserve(value.length());
    for (size_t i = 0; i < value.length(); ++i)
    {
        if (value[i] == '%')
        {
            if (i + 2 < value.length())
            {
                unsigned int hex_val;
                stringstream ss;
                ss << hex << value.substr(i + 1, 2);
                ss >> hex_val;
                result += static_cast<char>(hex_val);
                i += 2;
            }
        }
        else if (value[i] == '+')
        {
            result += ' ';
        }
        else
        {
            result += value[i];
        }
    }
    return result;
}

// ------------------ Transaction (For Blockchain Log) ------------------
struct Transaction
{
    string txid;
    string assetID;
    string action; // "CREATE", "TRANSFER"
    int newHolderID;
    long long timestamp;

    string to_json() const
    {
        ostringstream ss;
        ss << "{\"txid\":\"" << txid << "\",\"assetID\":\"" << json_escape(assetID)
           << "\",\"action\":\"" << json_escape(action) << "\",\"newHolderID\":" << newHolderID
           << ",\"timestamp\":" << timestamp << "}";
        return ss.str();
    }
};

// ------------------ BloomFilter (For Quick Verification) ------------------
struct BloomFilter
{
    size_t m, k;
    vector<uint8_t> bits;
    BloomFilter(size_t m_ = 4096, size_t k_ = 5) : m(m_), k(k_), bits((m + 7) / 8, 0) {}
    void setbit(size_t i) { bits[i / 8] |= (1 << (i % 8)); }
    bool getbit(size_t i) const { return bits[i / 8] & (1 << (i % 8)); }
    uint64_t hash_seed(const string &s, uint64_t seed) const
    {
        return strtoull(sha256_hex(s + "|" + to_string(seed)).substr(0, 16).c_str(), nullptr, 16);
    }
    void insert(const string &s)
    {
        for (size_t i = 0; i < k; i++)
            setbit(hash_seed(s, i) % m);
    }
    bool contains(const string &s) const
    {
        for (size_t i = 0; i < k; i++)
            if (!getbit(hash_seed(s, i) % m))
                return false;
        return true;
    }
};
BloomFilter GlobalAssetFilter; // Global filter for all valid Asset IDs

// ------------------ Block & Blockchain (For Audit Log) ------------------
string merkle_hash_pair(const string &a, const string &b) { return sha256_hex(a + "|" + b); }
struct Block
{
    int index;
    string prev_hash, merkle_root;
    vector<Transaction> txs;
    Block(int i = 0, string prev = "0") : index(i), prev_hash(prev) {}
    void add_tx(const Transaction &t)
    {
        txs.push_back(t);
    }
    void finalize()
    {
        vector<string> leaves;
        for (auto &t : txs)
            leaves.push_back(t.txid); // txid is already a hash
        if (leaves.empty())
        {
            merkle_root = sha256_hex("");
            return;
        }
        while (leaves.size() > 1)
        {
            vector<string> nxt;
            for (size_t i = 0; i < leaves.size(); i += 2)
            {
                if (i + 1 == leaves.size())
                    nxt.push_back(merkle_hash_pair(leaves[i], leaves[i]));
                else
                    nxt.push_back(merkle_hash_pair(leaves[i], leaves[i + 1]));
            }
            leaves.swap(nxt);
        }
        merkle_root = leaves[0];
    }
    string to_json() const
    {
        ostringstream ss;
        ss << "{\"index\":" << index << ",\"prev_hash\":\"" << prev_hash
           << "\",\"merkle_root\":\"" << merkle_root << "\",\"txs\":[";
        for (size_t i = 0; i < txs.size(); i++)
        {
            if (i)
                ss << ",";
            ss << txs[i].to_json();
        }
        ss << "]}";
        return ss.str();
    }
};

struct Blockchain
{
    vector<Block> chain;
    size_t max_txs_per_block = 6;

    // === BUG FIX v2.0 ===
    // Constructor now creates a finalized, empty Genesis Block.
    Blockchain()
    {
        chain.emplace_back(0, "0"); // Create Block 0
        chain.back().finalize();    // Finalize it (it's empty)
        cout << "Genesis Block 0 created and finalized." << endl;
    }

    Transaction make_tx(const string &assetID, const string &action, int newHolderID)
    {
        long long ts = chrono::high_resolution_clock::now().time_since_epoch().count();
        string base = assetID + "|" + action + "|" + to_string(newHolderID) + "|" + to_string(ts);
        Transaction t{sha256_hex(base), assetID, action, newHolderID, ts};
        return t;
    }

    // === BUG FIX v2.0 ===
    // This logic is now cleaner and 100% correct.
    void add_tx_to_chain(const Transaction &t)
    {
        // 1. Get the current block to add to.
        Block &current_block = chain.back();

        // 2. Check if this block is full.
        if (current_block.txs.size() >= max_txs_per_block)
        {
            // 3. If full, finalize it
            current_block.finalize();
            // 4. Create a new block, linking it to the one we just sealed
            chain.emplace_back(chain.size(), current_block.merkle_root);
        }

        // 5. Add the transaction to the current block
        // (which is either the old one, or the new one we just created)
        chain.back().add_tx(t);
    }

    string to_json() const
    {
        ostringstream ss;
        ss << "{\"blocks\":[";
        for (size_t i = 0; i < chain.size(); i++)
        {
            if (i)
                ss << ",";
            ss << chain[i].to_json();
        }
        ss << "]}";
        return ss.str();
    }
};
Blockchain GBC; // Our global blockchain log instance

// ------------------ Database Initialization & Loading ------------------
void initialize_database()
{
    char *zErrMsg = 0;

    const char *createUsersTable =
        "CREATE TABLE IF NOT EXISTS Users ("
        "UserID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "Name TEXT NOT NULL UNIQUE,"
        "Department TEXT);";

    const char *createAssetsTable =
        "CREATE TABLE IF NOT EXISTS Assets ("
        "AssetID TEXT PRIMARY KEY,"
        "Name TEXT NOT NULL,"
        "Status TEXT NOT NULL CHECK(Status IN ('Available', 'In Use', 'Repair')),"
        "CurrentHolderID INTEGER,"
        "FOREIGN KEY(CurrentHolderID) REFERENCES Users(UserID));";

    const char *createBlockchainLogTable =
        "CREATE TABLE IF NOT EXISTS BlockchainLog ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "TxID TEXT NOT NULL UNIQUE,"
        "AssetID TEXT NOT NULL,"
        "Action TEXT NOT NULL,"
        "NewHolderID INTEGER,"
        "Timestamp INTEGER NOT NULL);";

    sqlite3_exec(db, createUsersTable, 0, 0, &zErrMsg);
    sqlite3_exec(db, createAssetsTable, 0, 0, &zErrMsg);
    sqlite3_exec(db, createBlockchainLogTable, 0, 0, &zErrMsg);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM Users;", -1, &stmt, 0);
    if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0)
    {
        cout << "No users found. Adding default users." << endl;
        sqlite3_exec(db, "INSERT INTO Users (Name, Department) VALUES ('IT Office', 'Administration');", 0, 0, &zErrMsg);
        sqlite3_exec(db, "INSERT INTO Users (Name, Department) VALUES ('Prof. Smith', 'Computer Science');", 0, 0, &zErrMsg);
        sqlite3_exec(db, "INSERT INTO Users (Name, Department) VALUES ('Student Lab', 'Engineering');", 0, 0, &zErrMsg);
    }
    sqlite3_finalize(stmt);

    if (zErrMsg)
    {
        cerr << "SQL error: " << zErrMsg << endl;
        sqlite3_free(zErrMsg);
    }
    else
    {
        cout << "Database tables checked/created successfully." << endl;
    }
}

// Load existing data from DB into our in-memory structures
void load_system_on_startup()
{
    sqlite3_stmt *stmt;
    int asset_count = 0;

    // 1. Load all valid Asset IDs into the Bloom Filter
    string sql_assets = "SELECT AssetID FROM Assets;";
    if (sqlite3_prepare_v2(db, sql_assets.c_str(), -1, &stmt, 0) == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            string assetID = (const char *)sqlite3_column_text(stmt, 0);
            GlobalAssetFilter.insert(assetID);
            asset_count++;
        }
    }
    sqlite3_finalize(stmt);

    // 2. Load the entire transaction history into the in-memory blockchain
    string sql_log = "SELECT TxID, AssetID, Action, NewHolderID, Timestamp FROM BlockchainLog ORDER BY Timestamp ASC;";
    if (sqlite3_prepare_v2(db, sql_log.c_str(), -1, &stmt, 0) == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            Transaction t;
            t.txid = (const char *)sqlite3_column_text(stmt, 0);
            t.assetID = (const char *)sqlite3_column_text(stmt, 1);
            t.action = (const char *)sqlite3_column_text(stmt, 2);
            t.newHolderID = sqlite3_column_int(stmt, 3);
            t.timestamp = sqlite3_column_int64(stmt, 4);
            GBC.add_tx_to_chain(t);
        }
    }
    sqlite3_finalize(stmt);

    // === BUG FIX v2.0 ===
    // After loading, check if the last block (which is not full)
    // has a *previous* block that *is* full and needs finalizing.
    // This is the correct logic.
    if (GBC.chain.size() > 1)
    { // If there is more than just the genesis block
        Block &last_block = GBC.chain.back();
        Block &prev_block = GBC.chain[GBC.chain.size() - 2];

        // If the *previous* block is full and NOT finalized, finalize it.
        if (prev_block.txs.size() == GBC.max_txs_per_block && prev_block.merkle_root.empty())
        {
            cout << "Startup load: Finalizing previous block " << prev_block.index << "..." << endl;
            prev_block.finalize();
            // And update the current block's 'prev_hash' to match
            last_block.prev_hash = prev_block.merkle_root;
        }
    }

    cout << "System loaded. " << asset_count << " assets in filter, " << GBC.chain.size() << " blocks in memory." << endl;
}

// ------------------ HTTP Server ------------------
void send_response(SOCKET client, const string &body, const string &type = "application/json")
{
    ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\nContent-Type: " << type << "\r\nContent-Length: " << body.size()
         << "\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n"
         << body;
    string s = resp.str();
    send(client, s.c_str(), (int)s.size(), 0);
}

string sql_to_json(sqlite3_stmt *stmt)
{
    ostringstream ss;
    ss << "[";
    int col_count = sqlite3_column_count(stmt);
    bool first_row = true;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        if (!first_row)
            ss << ",";
        first_row = false;
        ss << "{";
        for (int i = 0; i < col_count; i++)
        {
            const char *col_name = sqlite3_column_name(stmt, i);
            const unsigned char *col_val_unsigned = sqlite3_column_text(stmt, i);
            const char *col_val = reinterpret_cast<const char *>(col_val_unsigned);

            if (sqlite3_column_type(stmt, i) == SQLITE_INTEGER || sqlite3_column_type(stmt, i) == SQLITE_FLOAT)
            {
                ss << "\"" << json_escape(col_name) << "\":" << (col_val ? col_val : "null");
            }
            else
            {
                ss << "\"" << json_escape(col_name) << "\":\"" << json_escape(col_val ? col_val : "NULL") << "\"";
            }

            if (i < col_count - 1)
                ss << ",";
        }
        ss << "}";
    }
    ss << "]";
    return ss.str();
}

DWORD WINAPI handle_client(LPVOID arg)
{
    SOCKET client_fd = (SOCKET)arg;
    char buf[8192];
    int r = recv(client_fd, buf, 8192 - 1, 0);
    if (r <= 0)
    {
        closesocket(client_fd);
        return 0;
    }
    buf[r] = 0;
    string req(buf);

    string method, path;
    {
        istringstream iss(req);
        iss >> method >> path;
    }

    if (method == "OPTIONS")
    {
        send(client_fd, "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n", 174, 0);
        closesocket(client_fd);
        return 0;
    }

    map<string, string> params;
    size_t qs = path.find('?');
    if (qs != string::npos)
    {
        string query = path.substr(qs + 1);
        istringstream qss(query);
        string kv;
        while (getline(qss, kv, '&'))
        {
            auto eq = kv.find('=');
            if (eq != string::npos)
            {
                params[kv.substr(0, eq)] = url_decode(kv.substr(eq + 1));
            }
        }
    }

    // --- API Endpoint: Get Dashboard Data ---
    if (path.find("/get_dashboard_data") == 0)
    {
        sqlite3_stmt *users_stmt;
        sqlite3_stmt *assets_stmt;
        string users_sql = "SELECT UserID, Name, Department FROM Users;";
        string assets_sql = "SELECT A.AssetID, A.Name, A.Status, U.Name as HolderName FROM Assets A LEFT JOIN Users U ON A.CurrentHolderID = U.UserID ORDER BY A.Name;";

        string users_json = "[]";
        if (sqlite3_prepare_v2(db, users_sql.c_str(), -1, &users_stmt, 0) == SQLITE_OK)
        {
            users_json = sql_to_json(users_stmt);
        }
        sqlite3_finalize(users_stmt);

        string assets_json = "[]";
        if (sqlite3_prepare_v2(db, assets_sql.c_str(), -1, &assets_stmt, 0) == SQLITE_OK)
        {
            assets_json = sql_to_json(assets_stmt);
        }
        sqlite3_finalize(assets_stmt);

        ostringstream ss;
        ss << "{\"users\":" << users_json << ",\"assets\":" << assets_json << "}";
        send_response(client_fd, ss.str());
    }

    // --- API Endpoint: Add User ---
    else if (path.find("/add_user") == 0)
    {
        try
        {
            string name = params["name"];
            string department = params["department"];

            if (name.empty() || department.empty())
            {
                throw runtime_error("Name and department are required.");
            }

            sqlite3_stmt *stmt;
            string sql = "INSERT INTO Users (Name, Department) VALUES (?, ?);";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, department.c_str(), -1, SQLITE_STATIC);

            int rc = sqlite3_step(stmt);

            if (rc == SQLITE_CONSTRAINT)
            {
                send_response(client_fd, "{\"ok\":false, \"error\":\"User name already exists\"}");
            }
            else if (rc != SQLITE_DONE)
            {
                send_response(client_fd, "{\"ok\":false, \"error\":\"Failed to add user to database.\"}");
            }
            else
            {
                send_response(client_fd, "{\"ok\":true}");
            }
            sqlite3_finalize(stmt);
        }
        catch (const exception &e)
        {
            send_response(client_fd, "{\"ok\":false, \"error\":\"Invalid parameters\"}");
        }
    }

    // --- API Endpoint: Add Asset ---
    else if (path.find("/add_asset") == 0)
    {
        try
        {
            string assetID = params["assetID"];
            string name = params["name"];
            int holderID = stoi(params["holderID"]);

            Transaction t = GBC.make_tx(assetID, "CREATE", holderID);

            sqlite3_stmt *stmt;
            string sql = "INSERT INTO Assets (AssetID, Name, Status, CurrentHolderID) VALUES (?, ?, 'Available', ?);";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_text(stmt, 1, t.assetID.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, t.newHolderID);

            int rc = sqlite3_step(stmt);

            if (rc == SQLITE_CONSTRAINT)
            {
                send_response(client_fd, "{\"ok\":false, \"error\":\"Asset ID already exists\"}");
            }
            else if (rc != SQLITE_DONE)
            {
                send_response(client_fd, "{\"ok\":false, \"error\":\"Failed to add asset to database\"}");
            }
            else
            {
                sqlite3_stmt *log_stmt;
                string log_sql = "INSERT INTO BlockchainLog (TxID, AssetID, Action, NewHolderID, Timestamp) VALUES (?, ?, ?, ?, ?);";
                sqlite3_prepare_v2(db, log_sql.c_str(), -1, &log_stmt, 0);
                sqlite3_bind_text(log_stmt, 1, t.txid.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(log_stmt, 2, t.assetID.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(log_stmt, 3, t.action.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int(log_stmt, 4, t.newHolderID);
                sqlite3_bind_int64(log_stmt, 5, t.timestamp);
                sqlite3_step(log_stmt);
                sqlite3_finalize(log_stmt);

                GBC.add_tx_to_chain(t);
                GlobalAssetFilter.insert(t.assetID);
                send_response(client_fd, "{\"ok\":true}");
            }
            sqlite3_finalize(stmt);
        }
        catch (const exception &e)
        {
            send_response(client_fd, "{\"ok\":false, \"error\":\"Invalid parameters\"}");
        }
    }

    // --- API Endpoint: Transfer Asset ---
    else if (path.find("/transfer_asset") == 0)
    {
        try
        {
            string assetID = params["assetID"];
            int newHolderID = stoi(params["newHolderID"]);

            Transaction t = GBC.make_tx(assetID, "TRANSFER", newHolderID);

            sqlite3_stmt *stmt;
            string sql = "UPDATE Assets SET CurrentHolderID = ?, Status = 'In Use' WHERE AssetID = ?;";
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
            sqlite3_bind_int(stmt, 1, t.newHolderID);
            sqlite3_bind_text(stmt, 2, t.assetID.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                send_response(client_fd, "{\"ok\":false, \"error\":\"Asset transfer failed\"}");
            }
            else
            {
                sqlite3_stmt *log_stmt;
                string log_sql = "INSERT INTO BlockchainLog (TxID, AssetID, Action, NewHolderID, Timestamp) VALUES (?, ?, ?, ?, ?);";
                sqlite3_prepare_v2(db, log_sql.c_str(), -1, &log_stmt, 0);
                sqlite3_bind_text(log_stmt, 1, t.txid.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(log_stmt, 2, t.assetID.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(log_stmt, 3, t.action.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int(log_stmt, 4, t.newHolderID);
                sqlite3_bind_int64(log_stmt, 5, t.timestamp);
                sqlite3_step(log_stmt);
                sqlite3_finalize(log_stmt);

                GBC.add_tx_to_chain(t);
                send_response(client_fd, "{\"ok\":true}");
            }
            sqlite3_finalize(stmt);
        }
        catch (const exception &e)
        {
            send_response(client_fd, "{\"ok\":false, \"error\":\"Invalid parameters\"}");
        }
    }

    // --- API Endpoint: Verify Asset (Bloom Filter) ---
    else if (path.find("/verify_asset") == 0)
    {
        string assetID = params["assetID"];
        bool found = GlobalAssetFilter.contains(assetID);
        send_response(client_fd, "{\"ok\":true, \"found\":" + string(found ? "true" : "false") + "}");
    }

    // --- API Endpoint: Get Blockchain Log ---
    else if (path.find("/get_blockchain_log") == 0)
    {
        send_response(client_fd, GBC.to_json());
    }

    // --- API Endpoint: Get Asset History (Graph Traversal) ---
    else if (path.find("/get_asset_history") == 0)
    {
        string assetID = params["assetID"];
        sqlite3_stmt *stmt;

        string sql = "SELECT L.Action, L.Timestamp, U.Name as HolderName FROM BlockchainLog L "
                     "LEFT JOIN Users U ON L.NewHolderID = U.UserID "
                     "WHERE L.AssetID = ? ORDER BY L.Timestamp ASC;";

        string history_json = "[]";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, assetID.c_str(), -1, SQLITE_STATIC);
            history_json = sql_to_json(stmt);
        }
        sqlite3_finalize(stmt);

        send_response(client_fd, history_json);
    }

    else
    {
        send_response(client_fd, "{\"error\":\"unknown path\"}");
    }

    closesocket(client_fd);
    return 0;
}

// ------------------ Main Server Function ------------------
void run_server(uint16_t port = 8080)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        cerr << "WSAStartup failed\n";
        return;
    }
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET)
    {
        cerr << "socket() failed\n";
        return;
    }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cerr << "bind() failed, Error: " << WSAGetLastError() << "\n";
        closesocket(srv);
        return;
    }
    if (listen(srv, 16) == SOCKET_ERROR)
    {
        cerr << "listen() failed\n";
        closesocket(srv);
        return;
    }

    cout << "Server listening on http://127.0.0.1:" << port << endl;

    while (server_running)
    {
        SOCKET fd = accept(srv, NULL, NULL);
        if (fd == INVALID_SOCKET)
        {
            if (!server_running)
                break;
            else
                continue;
        }
        CreateThread(NULL, 0, handle_client, (LPVOID)fd, 0, NULL);
    }
    closesocket(srv);
    WSACleanup();
}

int main()
{
    cout << "--- VerifAsset Backend v2.0 ---" << endl; // Version check

    int rc = sqlite3_open("college_assets.db", &db);
    if (rc)
    {
        cerr << "Can't open database: " << sqlite3_errcode(db) << ": " << sqlite3_errmsg(db) << endl;
        return 1;
    }
    else
    {
        cout << "Opened database 'college_assets.db' successfully." << endl;
    }

    initialize_database();
    load_system_on_startup();

    run_server(8080);

    sqlite3_close(db);
    return 0;
}
