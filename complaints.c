
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

static sqlite3 *db = NULL;

int init_db(const char *db_path) {
    int rc = sqlite3_open(db_path, &db);
    if (rc) return rc;
    const char *sql_users = "CREATE TABLE IF NOT EXISTS users ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "name TEXT NOT NULL, "
                      "email TEXT UNIQUE NOT NULL, "
                      "password TEXT NOT NULL, "
                      "is_warden BOOLEAN NOT NULL DEFAULT 0);";
    const char *sql_complaints = "CREATE TABLE IF NOT EXISTS complaints ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      "student_id INTEGER NOT NULL, "
                      "title TEXT NOT NULL, "
                      "category TEXT NOT NULL, "
                      "description TEXT NOT NULL, "
                      "proof_file TEXT, "
                      "status TEXT NOT NULL DEFAULT 'Pending', "
                      "remark TEXT, "
                      "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                      "FOREIGN KEY (student_id) REFERENCES users (id)"
                      ");";
    char *err = NULL;
    rc = sqlite3_exec(db, sql_users, 0, 0, &err);
    if (rc != SQLITE_OK) { if (err) sqlite3_free(err); return rc; }
    rc = sqlite3_exec(db, sql_complaints, 0, 0, &err);
    if (rc != SQLITE_OK) { if (err) sqlite3_free(err); return rc; }
    return SQLITE_OK;
}

int add_complaint(const char *db_path, int student_id, const char *title, const char *category, const char *description, const char *proof_file) {
    if (!db) {
        int rc = init_db(db_path);
        if (rc != SQLITE_OK) return rc;
    }
    const char *sql = "INSERT INTO complaints (student_id, title, category, description, proof_file) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;
    sqlite3_bind_int(stmt, 1, student_id);
    sqlite3_bind_text(stmt, 2, title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, category, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, description, -1, SQLITE_TRANSIENT);
    if (proof_file)
        sqlite3_bind_text(stmt, 5, proof_file, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 5);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return rc;
    return SQLITE_OK;
}

int update_status(const char *db_path, int complaint_id, const char *status) {
    if (!db) { int rc = init_db(db_path); if (rc != SQLITE_OK) return rc; }
    const char *sql = "UPDATE complaints SET status = ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;
    sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, complaint_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return rc;
    return SQLITE_OK;
}

int add_remark(const char *db_path, int complaint_id, const char *remark) {
    if (!db) { int rc = init_db(db_path); if (rc != SQLITE_OK) return rc; }
    const char *sql = "UPDATE complaints SET remark = ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return rc;
    sqlite3_bind_text(stmt, 1, remark, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, complaint_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return rc;
    return SQLITE_OK;
}

// Returns a malloc'd JSON string containing complaints for a student. Caller should free.
char* get_complaints_json_for_student(const char *db_path, int student_id) {
    if (!db) { int rc = init_db(db_path); if (rc != SQLITE_OK) return NULL; }
    const char *sql = "SELECT id, title, category, description, proof_file, status, remark, created_at FROM complaints WHERE student_id = ? ORDER BY created_at DESC;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    sqlite3_bind_int(stmt, 1, student_id);
    // Build JSON progressively
    size_t bufsize = 8192;
    char *buf = malloc(bufsize);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    size_t len = 0;
    len += snprintf(buf+len, bufsize-len, "[");
    int first = 1;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (!first) len += snprintf(buf+len, bufsize-len, ",");
        first = 0;
        int id = sqlite3_column_int(stmt,0);
        const unsigned char *title = sqlite3_column_text(stmt,1);
        const unsigned char *category = sqlite3_column_text(stmt,2);
        const unsigned char *description = sqlite3_column_text(stmt,3);
        const unsigned char *proof = sqlite3_column_text(stmt,4);
        const unsigned char *status = sqlite3_column_text(stmt,5);
        const unsigned char *remark = sqlite3_column_text(stmt,6);
        const unsigned char *created = sqlite3_column_text(stmt,7);
        // ensure buffer large enough
        if (bufsize - len < 512) {
            bufsize *= 2;
            char *nb = realloc(buf, bufsize);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
        }
        // naive JSON escaping (replace double quotes)
        char t[1024]; char c[256]; char d[2048]; char p[512]; char s[128]; char r[1024]; char cr[128];
        snprintf(t, sizeof(t), "%s", title? (const char*)title : "");
        snprintf(c, sizeof(c), "%s", category? (const char*)category : "");
        snprintf(d, sizeof(d), "%s", description? (const char*)description : "");
        snprintf(p, sizeof(p), "%s", proof? (const char*)proof : "");
        snprintf(s, sizeof(s), "%s", status? (const char*)status : "");
        snprintf(r, sizeof(r), "%s", remark? (const char*)remark : "");
        snprintf(cr, sizeof(cr), "%s", created? (const char*)created : "");
        len += snprintf(buf+len, bufsize-len,
            "{\"id\":%d,\"title\":\"%s\",\"category\":\"%s\",\"description\":\"%s\",\"proof_file\":\"%s\",\"status\":\"%s\",\"remark\":\"%s\",\"created_at\":\"%s\"}",
            id, t, c, d, p, s, r, cr
        );
    }
    len += snprintf(buf+len, bufsize-len, "]");
    sqlite3_finalize(stmt);
    return buf;
}

int list_complaints_count(const char *db_path) {
    if (!db) { int rc = init_db(db_path); if (rc != SQLITE_OK) return -1; }
    const char *sql = "SELECT COUNT(*) FROM complaints;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    rc = sqlite3_step(stmt);
    int count = 0;
    if (rc == SQLITE_ROW) count = sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    return count;
}

int close_lib() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
    return 0;
}
