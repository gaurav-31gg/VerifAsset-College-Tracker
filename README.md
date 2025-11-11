# VerifAsset-College-Tracker
A hybrid C++/SQLite project for Data Structures class.
VerifAsset: A Hybrid Database-Blockchain Asset Tracker

This is a Data Structures project that demonstrates a hybrid data management system for a "VerifAsset - Secure College Asset Tracker."

It combines a high-speed, persistent B-Tree (via SQLite) with an immutable Blockchain (using Merkle Trees) and a high-performance Bloom Filter for verification.

Core Data Structures

B-Tree (SQLite): Manages the "current state" of all assets and users for fast, real-time dashboard queries.

Merkle Tree (Blockchain): Provides a secure, tamper-proof "audit log" of all asset transactions (creates, transfers).

Bloom Filter (Probabilistic Hash Table): Provides an instant, $O(1)$ "Quick Verify" feature to detect fraudulent or unregistered asset IDs.

Graph (via SQL JOIN): The "Show History" feature performs a graph traversal (using a SQL JOIN on the log) to find the complete path of an asset.

How to Compile and Run (Windows/g++)

This project requires the sqlite3 amalgamation files (sqlite3.c and sqlite3.h).

1. Compile the C (SQLite) Code:

g++ -c -x c sqlite3.c -o sqlite3.o -DSQLITE_OMIT_DATETIME_FUNCS


2. Compile the C++ (App) Code and Link:

g++ -std=c++17 -fpermissive main.cpp sqlite3.o -o server.exe -lws2_32


3. Run the Server:

.\server.exe


4. Open the Frontend:
Open the index.html file in any modern web browser.
