/* server.c
   Hostel Complaint System - C backend (libmicrohttpd + sqlite3)
   - Student register/login by email+password
   - Warden login (default warden/wardenpass)
   - Complaint add/view, file upload (5MB), analytics endpoint
   - Sessions expire after 24 hours
   - Uses PORT env (Render)
*/

#define _GNU_SOURCE
#include <microhttpd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#define UPLOAD_LIMIT_BYTES (5 * 1024 * 1024) /* 5 MB */
#define SESSION_EXPIRE_SECONDS (24 * 3600)   /* 24 hours */

static sqlite3 *db = NULL;

#ifndef MHD_USE_INTERNAL_POLLING_THREAD
#define MHD_USE_INTERNAL_POLLING_THREAD 0x0001
#endif
#define MHD_THREAD_FLAG MHD_USE_INTERNAL_POLLING_THREAD

/* ---------- utilities ---------- */

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void ensure_uploads_dir(void) {
    mkdir("uploads", 0755);
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    if (out_len) *out_len = len;
    return buf;
}

static int send_file(struct MHD_Connection *connection, const char *path, const char *mime) {
    size_t len;
    char *data = read_file(path, &len);
    if (!data) return MHD_NO;
    struct MHD_Response *response = MHD_create_response_from_buffer(len, (void *)data, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", mime);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            char aa = a, bb = b;
            if (aa >= 'a') aa -= 'a' - 'A';
            if (aa >= 'A') aa -= ('A' - 10); else aa -= '0';
            if (bb >= 'a') bb -= 'a' - 'A';
            if (bb >= 'A') bb -= ('A' - 10); else bb -= '0';
            *dst++ = 16 * aa + bb;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

static char *generate_token(void) {
    static const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char *token = malloc(33);
    if (!token) return NULL;
    srand((unsigned)time(NULL) ^ getpid());
    for (int i = 0; i < 32; ++i) token[i] = chars[rand() % (int)strlen(chars)];
    token[32] = '\0';
    return token;
}

static int respond_json(struct MHD_Connection *connection, const char *json, int status) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* ---------- DB init ---------- */

static int init_db(void) {
    char *err = 0;
    const char *sql_users =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT, "
        "email TEXT UNIQUE, "
        "password TEXT, "
        "role TEXT DEFAULT 'student', "
        "room TEXT"
        ");";
    const char *sql_complaints =
        "CREATE TABLE IF NOT EXISTS complaints ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER, "
        "title TEXT, "
        "type TEXT, "
        "description TEXT, "
        "filename TEXT, "
        "status TEXT DEFAULT 'Pending', "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";
    const char *sql_sessions =
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token TEXT PRIMARY KEY, "
        "user_id INTEGER, "
        "created_at INTEGER, "
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";

    if (sqlite3_exec(db, sql_users, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error users: %s\n", err);
        sqlite3_free(err);
        return 1;
    }
    if (sqlite3_exec(db, sql_complaints, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error complaints: %s\n", err);
        sqlite3_free(err);
        return 1;
    }
    if (sqlite3_exec(db, sql_sessions, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error sessions: %s\n", err);
        sqlite3_free(err);
        return 1;
    }

    /* default warden */
    const char *ins = "INSERT OR IGNORE INTO users (name,email,password,role) VALUES ('Warden','warden@hostel','wardenpass','warden');";
    if (sqlite3_exec(db, ins, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL insert warden error: %s\n", err);
        sqlite3_free(err);
    }

    return 0;
}

/* ---------- sessions ---------- */

static int token_user_id(const char *token) {
    if (!token || !*token) return 0;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT user_id, created_at FROM sessions WHERE token = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return 0; }
    int user_id = sqlite3_column_int(stmt, 0);
    long created = (long)sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);
    long now = time(NULL);
    if (now - created > SESSION_EXPIRE_SECONDS) {
        /* expired - delete */
        sqlite3_stmt *del = NULL;
        const char *dsql = "DELETE FROM sessions WHERE token = ?;";
        if (sqlite3_prepare_v2(db, dsql, -1, &del, NULL) == SQLITE_OK) {
            sqlite3_bind_text(del, 1, token, -1, SQLITE_TRANSIENT);
            sqlite3_step(del);
            sqlite3_finalize(del);
        }
        return 0;
    }
    return user_id;
}

/* ---------- API handlers ---------- */

/* Register: expects name, email, password, room */
static int handle_api_register(struct MHD_Connection *connection, const unsigned char *body, size_t body_len) {
    char name[128] = {0}, email[128] = {0}, password[128] = {0}, room[64] = {0};
    char *tmp = malloc(body_len + 1);
    if (!tmp) return respond_json(connection, "{\"status\":\"error\",\"message\":\"alloc\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    memcpy(tmp, body, body_len);
    tmp[body_len] = '\0';
    char *p = strtok(tmp, "&");
    while (p) {
        if (strncmp(p, "name=", 5) == 0) url_decode(name, p + 5);
        else if (strncmp(p, "email=", 6) == 0) url_decode(email, p + 6);
        else if (strncmp(p, "password=", 9) == 0) url_decode(password, p + 9);
        else if (strncmp(p, "room=", 5) == 0) url_decode(room, p + 5);
        p = strtok(NULL, "&");
    }
    free(tmp);

    if (strlen(email) == 0 || strlen(password) == 0) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"email/password required\"}", MHD_HTTP_BAD_REQUEST);
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO users (name,email,password,room,role) VALUES (?, ?, ?, ?, 'student');";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, room, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"user exists or db error\"}", MHD_HTTP_CONFLICT);
    }
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* Login: email + password */
static int handle_api_login(struct MHD_Connection *connection, const unsigned char *body, size_t body_len) {
    char email[128] = {0}, password[128] = {0};
    char *tmp = malloc(body_len + 1);
    if (!tmp) return respond_json(connection, "{\"status\":\"error\",\"message\":\"alloc\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    memcpy(tmp, body, body_len);
    tmp[body_len] = '\0';
    char *p = strtok(tmp, "&");
    while (p) {
        if (strncmp(p, "email=", 6) == 0) url_decode(email, p + 6);
        else if (strncmp(p, "password=", 9) == 0) url_decode(password, p + 9);
        p = strtok(NULL, "&");
    }
    free(tmp);

    if (strlen(email) == 0 || strlen(password) == 0) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"email/password required\"}", MHD_HTTP_BAD_REQUEST);
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT id, password, role FROM users WHERE email = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid credentials\"}", MHD_HTTP_UNAUTHORIZED); }
    int user_id = sqlite3_column_int(stmt, 0);
    const unsigned char *dbpass = sqlite3_column_text(stmt, 1);
    const unsigned char *dbrole = sqlite3_column_text(stmt, 2);
    if (!dbpass || strcmp((const char *)dbpass, password) != 0) {
        sqlite3_finalize(stmt);
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid credentials\"}", MHD_HTTP_UNAUTHORIZED);
    }
    sqlite3_finalize(stmt);

    char *token = generate_token();
    sqlite3_stmt *ins = NULL;
    const char *sql_ins = "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql_ins, -1, &ins, NULL) != SQLITE_OK) { free(token); return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR); }
    sqlite3_bind_text(ins, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(ins, 2, user_id);
    sqlite3_bind_int64(ins, 3, (sqlite3_int64)time(NULL));
    sqlite3_step(ins);
    sqlite3_finalize(ins);

    char resp[512];
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"token\":\"%s\",\"role\":\"%s\"}", token, dbrole ? (const char *)dbrole : "student");
    int ret = respond_json(connection, resp, MHD_HTTP_OK);
    free(token);
    return ret;
}

/* Get complaints (student: own; warden: all) */
static int handle_api_complaints_get(struct MHD_Connection *connection, const char *token) {
    int user_id = token_user_id(token);
    if (!user_id) return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED);

    sqlite3_stmt *stmt = NULL;
    const char *sql_role = "SELECT role FROM users WHERE id = (SELECT user_id FROM sessions WHERE token = ?);";
    if (sqlite3_prepare_v2(db, sql_role, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    const char *role = "student";
    if (rc == SQLITE_ROW && sqlite3_column_text(stmt, 0)) role = (const char *)sqlite3_column_text(stmt, 0);
    sqlite3_finalize(stmt);

    const char *q_all = "SELECT complaints.id, users.name, users.email, complaints.title, complaints.type, complaints.description, complaints.filename, complaints.status, complaints.created_at FROM complaints JOIN users ON users.id = complaints.user_id ORDER BY complaints.id DESC;";
    const char *q_user = "SELECT complaints.id, users.name, users.email, complaints.title, complaints.type, complaints.description, complaints.filename, complaints.status, complaints.created_at FROM complaints JOIN users ON users.id = complaints.user_id WHERE user_id = ? ORDER BY complaints.id DESC;";
    sqlite3_stmt *qstmt = NULL;
    if (strcmp(role, "warden") == 0) {
        if (sqlite3_prepare_v2(db, q_all, -1, &qstmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    } else {
        if (sqlite3_prepare_v2(db, q_user, -1, &qstmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
        sqlite3_bind_int(qstmt, 1, user_id);
    }

    char json[32768];
    strcpy(json, "{\"status\":\"ok\",\"complaints\":[");
    int first = 1;
    while ((rc = sqlite3_step(qstmt)) == SQLITE_ROW) {
        if (!first) strcat(json, ",");
        first = 0;
        int cid = sqlite3_column_int(qstmt, 0);
        const unsigned char *name = sqlite3_column_text(qstmt, 1);
        const unsigned char *email = sqlite3_column_text(qstmt, 2);
        const unsigned char *title = sqlite3_column_text(qstmt, 3);
        const unsigned char *ctype = sqlite3_column_text(qstmt, 4);
        const unsigned char *desc = sqlite3_column_text(qstmt, 5);
        const unsigned char *fname = sqlite3_column_text(qstmt, 6);
        const unsigned char *status = sqlite3_column_text(qstmt, 7);
        const unsigned char *created = sqlite3_column_text(qstmt, 8);

        char item[2048];
        snprintf(item, sizeof(item),
                 "{\"id\":%d,\"name\":\"%s\",\"email\":\"%s\",\"title\":\"%s\",\"type\":\"%s\",\"description\":\"%s\",\"filename\":\"%s\",\"status\":\"%s\",\"created\":\"%s\"}",
                 cid,
                 name ? (const char *)name : "",
                 email ? (const char *)email : "",
                 title ? (const char *)title : "",
                 ctype ? (const char *)ctype : "",
                 desc ? (const char *)desc : "",
                 fname ? (const char *)fname : "",
                 status ? (const char *)status : "",
                 created ? (const char *)created : "");
        strcat(json, item);
    }
    sqlite3_finalize(qstmt);
    strcat(json, "]}");
    return respond_json(connection, json, MHD_HTTP_OK);
}

/* Post complaint */
static int handle_api_complaint_post(struct MHD_Connection *connection, const unsigned char *body, size_t body_len, const char *token) {
    int user_id = token_user_id(token);
    if (!user_id) return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED);

    char title[256] = {0}, description[1024] = {0}, ctype[64] = {0}, filename[256] = {0};
    char *tmp = malloc(body_len + 1);
    if (!tmp) return respond_json(connection, "{\"status\":\"error\",\"message\":\"alloc\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    memcpy(tmp, body, body_len);
    tmp[body_len] = '\0';
    char *p = strtok(tmp, "&");
    while (p) {
        if (strncmp(p, "title=", 6) == 0) url_decode(title, p + 6);
        else if (strncmp(p, "description=", 12) == 0) url_decode(description, p + 12);
        else if (strncmp(p, "type=", 5) == 0) url_decode(ctype, p + 5);
        else if (strncmp(p, "filename=", 9) == 0) url_decode(filename, p + 9);
        p = strtok(NULL, "&");
    }
    free(tmp);
    if (strlen(title) == 0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"title required\"}", MHD_HTTP_BAD_REQUEST);

    sqlite3_stmt *ins = NULL;
    const char *sql_ins = "INSERT INTO complaints (user_id,title,type,description,filename) VALUES (?,?,?,?,?);";
    if (sqlite3_prepare_v2(db, sql_ins, -1, &ins, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_int(ins, 1, user_id);
    sqlite3_bind_text(ins, 2, title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, ctype, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 4, description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 5, filename, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* Update complaint status (warden) */
static int handle_api_complaint_update(struct MHD_Connection *connection, const unsigned char *body, size_t body_len, const char *token) {
    int user_id = token_user_id(token);
    if (!user_id) return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED);

    sqlite3_stmt *stmt = NULL;
    const char *sql_role = "SELECT users.role FROM users JOIN sessions ON users.id = sessions.user_id WHERE sessions.token = ?;";
    if (sqlite3_prepare_v2(db, sql_role, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED); }
    const unsigned char *role = sqlite3_column_text(stmt, 0);
    if (!role || strcmp((const char *)role, "warden") != 0) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"not authorized\"}", MHD_HTTP_FORBIDDEN); }
    sqlite3_finalize(stmt);

    int id = 0;
    char status[64] = {0};
    char *tmp = malloc(body_len + 1);
    if (!tmp) return respond_json(connection, "{\"status\":\"error\",\"message\":\"alloc\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    memcpy(tmp, body, body_len);
    tmp[body_len] = '\0';
    char *p = strtok(tmp, "&");
    while (p) {
        if (strncmp(p, "id=", 3) == 0) id = atoi(p + 3);
        else if (strncmp(p, "status=", 7) == 0) url_decode(status, p + 7);
        p = strtok(NULL, "&");
    }
    free(tmp);
    if (id == 0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"id required\"}", MHD_HTTP_BAD_REQUEST);

    sqlite3_stmt *upd = NULL;
    const char *sql_upd = "UPDATE complaints SET status = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql_upd, -1, &upd, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(upd, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(upd, 2, id);
    rc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (rc != SQLITE_DONE) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* Upload binary (X-FILENAME header) */
static int handle_upload_binary(struct MHD_Connection *connection, const char *upload_filename, const unsigned char *data, size_t size) {
    if (!upload_filename || size == 0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"no file\"}", MHD_HTTP_BAD_REQUEST);
    if (size > UPLOAD_LIMIT_BYTES) return respond_json(connection, "{\"status\":\"error\",\"message\":\"file too large\"}", MHD_HTTP_BAD_REQUEST);

    char fname[256];
    int j = 0;
    for (size_t i = 0; upload_filename[i] && j < 250; ++i) {
        if (upload_filename[i] == '/' || upload_filename[i] == '\\') continue;
        fname[j++] = upload_filename[i];
    }
    fname[j] = '\0';

    char path[512];
    snprintf(path, sizeof(path), "uploads/%s", fname);
    FILE *f = fopen(path, "wb");
    if (!f) return respond_json(connection, "{\"status\":\"error\",\"message\":\"cannot save\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    fwrite(data, 1, size, f);
    fclose(f);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* Analytics endpoint (simple): returns counts by type and by status */
static int handle_api_analytics(struct MHD_Connection *connection, const char *token) {
    int user_id = token_user_id(token);
    if (!user_id) return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED);

    /* only warden allowed */
    sqlite3_stmt *stmt = NULL;
    const char *sql_role = "SELECT users.role FROM users JOIN sessions ON users.id = sessions.user_id WHERE sessions.token = ?;";
    if (sqlite3_prepare_v2(db, sql_role, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED); }
    const unsigned char *role = sqlite3_column_text(stmt, 0);
    if (!role || strcmp((const char *)role, "warden") != 0) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"not authorized\"}", MHD_HTTP_FORBIDDEN); }
    sqlite3_finalize(stmt);

    /* counts by type */
    const char *sql_type = "SELECT type, COUNT(*) FROM complaints GROUP BY type;";
    const char *sql_status = "SELECT status, COUNT(*) FROM complaints GROUP BY status;";
    sqlite3_stmt *s1 = NULL, *s2 = NULL;
    char json[8192];
    strcpy(json, "{\"status\":\"ok\",\"by_type\":[");
    int first = 1;
    if (sqlite3_prepare_v2(db, sql_type, -1, &s1, NULL) == SQLITE_OK) {
        while ((rc = sqlite3_step(s1)) == SQLITE_ROW) {
            if (!first) strcat(json, ",");
            first = 0;
            const unsigned char *type = sqlite3_column_text(s1, 0);
            int cnt = sqlite3_column_int(s1, 1);
            char item[256];
            snprintf(item, sizeof(item), "{\"type\":\"%s\",\"count\":%d}", type ? (const char *)type : "", cnt);
            strcat(json, item);
        }
        sqlite3_finalize(s1);
    }
    strcat(json, "],\"by_status\":[");
    first = 1;
    if (sqlite3_prepare_v2(db, sql_status, -1, &s2, NULL) == SQLITE_OK) {
        while ((rc = sqlite3_step(s2)) == SQLITE_ROW) {
            if (!first) strcat(json, ",");
            first = 0;
            const unsigned char *status = sqlite3_column_text(s2, 0);
            int cnt = sqlite3_column_int(s2, 1);
            char item[256];
            snprintf(item, sizeof(item), "{\"status\":\"%s\",\"count\":%d}", status ? (const char *)status : "", cnt);
            strcat(json, item);
        }
        sqlite3_finalize(s2);
    }
    strcat(json, "]}");
    return respond_json(connection, json, MHD_HTTP_OK);
}

/* ---------- connection handler ---------- */

struct connection_info_struct {
    unsigned char *buffer;
    size_t size;
};

static struct connection_info_struct *connection_info_create(void) {
    struct connection_info_struct *ci = malloc(sizeof(*ci));
    if (!ci) return NULL;
    ci->buffer = NULL;
    ci->size = 0;
    return ci;
}
static void connection_info_free(struct connection_info_struct *ci) {
    if (!ci) return;
    if (ci->buffer) free(ci->buffer);
    free(ci);
}

static int answer_to_connection(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "GET") == 0) {
        /* map URLs to your template filenames */
        if (strcmp(url, "/") == 0) return send_file(connection, "templates/index.html", "text/html");
        if (strcmp(url, "/add_complaint") == 0) return send_file(connection, "templates/add_complaint.html", "text/html");
        if (strcmp(url, "/analytics") == 0) return send_file(connection, "templates/analytics.html", "text/html");
        if (strcmp(url, "/my_complaints") == 0) return send_file(connection, "templates/my_complaints.html", "text/html");
        if (strcmp(url, "/profile") == 0) return send_file(connection, "templates/profile.html", "text/html");
        if (strcmp(url, "/student_dashboard") == 0) return send_file(connection, "templates/student_dashboard.html", "text/html");
        if (strcmp(url, "/student_login") == 0) return send_file(connection, "templates/student_login.html", "text/html");
        if (strcmp(url, "/student_register") == 0) return send_file(connection, "templates/student_register.html", "text/html");
        if (strcmp(url, "/warden_dashboard") == 0) return send_file(connection, "templates/warden_dashboard.html", "text/html");
        if (strcmp(url, "/warden_login") == 0) return send_file(connection, "templates/warden_login.html", "text/html");

        if (strncmp(url, "/static/", 8) == 0) {
            char path[512];
            snprintf(path, sizeof(path), ".%s", url);
            const char *mime = "text/plain";
            if (strstr(path, ".css")) mime = "text/css";
            if (strstr(path, ".js")) mime = "application/javascript";
            if (strstr(path, ".png")) mime = "image/png";
            if (strstr(path, ".jpg") || strstr(path, ".jpeg")) mime = "image/jpeg";
            if (file_exists(path)) return send_file(connection, path, mime);
        }
        if (strncmp(url, "/uploads/", 8) == 0) {
            char path[512];
            snprintf(path, sizeof(path), ".%s", url);
            if (file_exists(path)) return send_file(connection, path, "application/octet-stream");
        }

        /* API GETs */
        if (strcmp(url, "/api/complaints") == 0) {
            const char *token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
            if (!token) token = "";
            return handle_api_complaints_get(connection, token);
        }
        if (strcmp(url, "/api/analytics") == 0) {
            const char *token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
            if (!token) token = "";
            return handle_api_analytics(connection, token);
        }

        const char *nf = "Not Found";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(nf), (void *)nf, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
        MHD_destroy_response(resp);
        return ret;
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(url, "/api/register") == 0 || strcmp(url, "/api/login") == 0 || strcmp(url, "/api/complaint") == 0 || strcmp(url, "/api/complaint/update") == 0 || strcmp(url, "/upload") == 0) {
            if (*con_cls == NULL) {
                struct connection_info_struct *ci = connection_info_create();
                *con_cls = ci;
                return MHD_YES;
            }
            struct connection_info_struct *ci = *con_cls;
            if (*upload_data_size) {
                size_t prev = ci->size;
                size_t add = *upload_data_size;
                if (prev + add > UPLOAD_LIMIT_BYTES + 1024) {
                    *upload_data_size = 0;
                    return respond_json(connection, "{\"status\":\"error\",\"message\":\"file too large\"}", MHD_HTTP_BAD_REQUEST);
                }
                ci->buffer = realloc(ci->buffer, prev + add);
                memcpy(ci->buffer + prev, upload_data, add);
                ci->size = prev + add;
                *upload_data_size = 0;
                return MHD_YES;
            } else {
                const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
                const char *xfn = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-FILENAME");
                if (strcmp(url, "/api/register") == 0) {
                    int ret = handle_api_register(connection, ci->buffer ? ci->buffer : (unsigned char *)"", ci->size);
                    connection_info_free(ci);
                    *con_cls = NULL;
                    return ret;
                } else if (strcmp(url, "/api/login") == 0) {
                    int ret = handle_api_login(connection, ci->buffer ? ci->buffer : (unsigned char *)"", ci->size);
                    connection_info_free(ci);
                    *con_cls = NULL;
                    return ret;
                } else if (strcmp(url, "/api/complaint") == 0) {
                    int ret = handle_api_complaint_post(connection, ci->buffer ? ci->buffer : (unsigned char *)"", ci->size, auth ? auth : "");
                    connection_info_free(ci);
                    *con_cls = NULL;
                    return ret;
                } else if (strcmp(url, "/api/complaint/update") == 0) {
                    int ret = handle_api_complaint_update(connection, ci->buffer ? ci->buffer : (unsigned char *)"", ci->size, auth ? auth : "");
                    connection_info_free(ci);
                    *con_cls = NULL;
                    return ret;
                } else if (strcmp(url, "/upload") == 0) {
                    int ret = handle_upload_binary(connection, xfn ? xfn : "upload.bin", ci->buffer ? ci->buffer : (unsigned char *)"", ci->size);
                    connection_info_free(ci);
                    *con_cls = NULL;
                    return ret;
                }
            }
        }
    }

    return respond_json(connection, "{\"status\":\"error\",\"message\":\"unsupported\"}", MHD_HTTP_BAD_REQUEST);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    char *port_env = getenv("PORT");
    int PORT = port_env ? atoi(port_env) : 8080;

    ensure_uploads_dir();

    if (sqlite3_open("hostel.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open DB: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    if (init_db()) return 1;

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_THREAD_FLAG,
        PORT,
        NULL,
        NULL,
        &answer_to_connection,
        NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        sqlite3_close(db);
        return 1;
    }

    printf("Server running on port %d\n", PORT);

    while (1) sleep(3600);

    MHD_stop_daemon(daemon);
    sqlite3_close(db);
    return 0;
}
