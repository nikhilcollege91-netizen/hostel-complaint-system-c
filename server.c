
/*
Hostel Complaint System - C backend using libmicrohttpd + sqlite3
This server serves static templates and exposes API endpoints:
- GET /, /login, /register, /student_dashboard, etc. serve HTML from templates/
- GET /static/* serve static assets
- POST /api/register  (application/x-www-form-urlencoded)
- POST /api/login     (application/x-www-form-urlencoded)
- GET  /api/complaints  (Authorization: token) -> returns JSON list
- POST /api/complaint   (Authorization: token) -> form fields title,description, type, filename
- POST /api/complaint/update (Authorization: token) -> id, status
- POST /upload -> raw body, header X-FILENAME: name (Authorization optional)
Notes:
- This is a prototype. Improve password hashing, input sanitization and multipart handling before production.
*/

#include <microhttpd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#define PORT 8080

static sqlite3 *db = NULL;

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void ensure_uploads_dir() {
    mkdir("uploads", 0755);
}

static int init_db(void) {
    char *err = 0;
    const char *sql_users =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE, "
        "email TEXT, "
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
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";
    if (sqlite3_exec(db, sql_users, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error users: %s\n", err); sqlite3_free(err); return 1;
    }
    if (sqlite3_exec(db, sql_complaints, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error complaints: %s\n", err); sqlite3_free(err); return 1;
    }
    if (sqlite3_exec(db, sql_sessions, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error sessions: %s\n", err); sqlite3_free(err); return 1;
    }
    /* Insert default warden if not exists */
    const char *ins = "INSERT OR IGNORE INTO users (username,password,role) VALUES ('warden','wardenpass','warden');";
    if (sqlite3_exec(db, ins, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error insert warden: %s\n", err); sqlite3_free(err);
    }
    return 0;
}

/* Read whole file */
static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = 0;
    fclose(f);
    if (out_len) *out_len = len;
    return buf;
}

/* Helper: send file from templates or static */
static int send_file(struct MHD_Connection *connection, const char *path, const char *mime) {
    size_t len;
    char *data = read_file(path, &len);
    if (!data) return MHD_NO;
    struct MHD_Response *response = MHD_create_response_from_buffer(len, (void*)data, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", mime);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

/* URL-decode (simple) */
static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10); else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10); else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' '; src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

/* Generate simple random token */
static char *generate_token(void) {
    static const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char *token = malloc(33);
    srand((unsigned)time(NULL) ^ getpid());
    for (int i = 0; i < 32; ++i) token[i] = chars[rand() % (strlen(chars))];
    token[32] = 0;
    return token;
}

/* Exec simple SQL safely using prepared statements for inserts where possible */
static int exec_sql(const char *sql) {
    char *err = 0;
    if (sqlite3_exec(db, sql, 0, 0, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL error exec: %s\nSQL: %s\n", err, sql);
        sqlite3_free(err);
        return 1;
    }
    return 0;
}

/* Handlers for API endpoints (simple JSON responses) */

static int respond_json(struct MHD_Connection *connection, const char *json, int status) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(json), (void*)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* POST /api/register */
static int handle_api_register(struct MHD_Connection *connection, const char *body) {
    char username[128] = {0}, password[128] = {0}, email[128] = {0}, room[64] = {0};
    char *b = strdup(body);
    char *p = strtok(b, "&");
    while (p) {
        if (strncmp(p, "username=", 9) == 0) url_decode(username, p + 9);
        if (strncmp(p, "password=", 9) == 0) url_decode(password, p + 9);
        if (strncmp(p, "email=", 6) == 0) url_decode(email, p + 6);
        if (strncmp(p, "room=", 5) == 0) url_decode(room, p + 5);
        p = strtok(NULL, "&");
    }
    free(b);
    if (strlen(username) == 0 || strlen(password) == 0) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"username/password required\"}", MHD_HTTP_BAD_REQUEST);
    }
    /* Use prepared statement to avoid SQL injection */
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO users (username,email,password,room,role) VALUES (?, ?, ?, ?, 'student');";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
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

/* POST /api/login */
static int handle_api_login(struct MHD_Connection *connection, const char *body) {
    char username[128] = {0}, password[128] = {0};
    char *b = strdup(body);
    char *p = strtok(b, "&");
    while (p) {
        if (strncmp(p, "username=", 9) == 0) url_decode(username, p + 9);
        if (strncmp(p, "password=", 9) == 0) url_decode(password, p + 9);
        p = strtok(NULL, "&");
    }
    free(b);
    if (strlen(username) == 0 || strlen(password) == 0) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"username/password required\"}", MHD_HTTP_BAD_REQUEST);
    }
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, password, role FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid credentials\"}", MHD_HTTP_UNAUTHORIZED);
    }
    int user_id = sqlite3_column_int(stmt, 0);
    const unsigned char *dbpass = sqlite3_column_text(stmt, 1);
    const unsigned char *dbrole = sqlite3_column_text(stmt, 2);
    if (strcmp((const char*)dbpass, password) != 0) {
        sqlite3_finalize(stmt);
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid credentials\"}", MHD_HTTP_UNAUTHORIZED);
    }
    sqlite3_finalize(stmt);
    char *token = generate_token();
    sqlite3_stmt *ins;
    const char *sql_ins = "INSERT INTO sessions (token,user_id) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql_ins, -1, &ins, NULL) != SQLITE_OK) {
        free(token);
        return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    sqlite3_bind_text(ins, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(ins, 2, user_id);
    sqlite3_step(ins);
    sqlite3_finalize(ins);
    char resp[512];
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"token\":\"%s\",\"role\":\"%s\"}", token, dbrole ? (const char*)dbrole : "student");
    int ret = respond_json(connection, resp, MHD_HTTP_OK);
    free(token);
    return ret;
}

/* GET /api/complaints */
static int handle_api_complaints_get(struct MHD_Connection *connection, const char *token) {
    if (!token || strlen(token)==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"no token\"}", MHD_HTTP_UNAUTHORIZED);
    sqlite3_stmt *stmt;
    const char *sql_uid = "SELECT user_id FROM sessions WHERE token = ?;";
    if (sqlite3_prepare_v2(db, sql_uid, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED); }
    int user_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    /* get role */
    const char *sql_role = "SELECT role FROM users WHERE id = (SELECT user_id FROM sessions WHERE token = ?);";
    if (sqlite3_prepare_v2(db, sql_role, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    const char *role = "student";
    if (rc == SQLITE_ROW && sqlite3_column_text(stmt,0)) role = (const char*)sqlite3_column_text(stmt,0);
    sqlite3_finalize(stmt);
    const char *q_all = "SELECT complaints.id, users.username, complaints.title, complaints.type, complaints.description, complaints.filename, complaints.status, complaints.created_at FROM complaints JOIN users ON users.id = complaints.user_id ORDER BY complaints.id DESC;";
    const char *q_user = "SELECT complaints.id, users.username, complaints.title, complaints.type, complaints.description, complaints.filename, complaints.status, complaints.created_at FROM complaints JOIN users ON users.id = complaints.user_id WHERE user_id = ? ORDER BY complaints.id DESC;";
    sqlite3_stmt *qstmt;
    if (strcmp(role, "warden") == 0) {
        if (sqlite3_prepare_v2(db, q_all, -1, &qstmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    } else {
        if (sqlite3_prepare_v2(db, q_user, -1, &qstmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
        sqlite3_bind_int(qstmt, 1, user_id);
    }
    char json[20000];
    strcpy(json, "{\"status\":\"ok\",\"complaints\":[");
    int first = 1;
    while ((rc = sqlite3_step(qstmt)) == SQLITE_ROW) {
        if (!first) strcat(json, ","); first = 0;
        int cid = sqlite3_column_int(qstmt,0);
        const unsigned char *uname = sqlite3_column_text(qstmt,1);
        const unsigned char *title = sqlite3_column_text(qstmt,2);
        const unsigned char *ctype = sqlite3_column_text(qstmt,3);
        const unsigned char *desc = sqlite3_column_text(qstmt,4);
        const unsigned char *fname = sqlite3_column_text(qstmt,5);
        const unsigned char *status = sqlite3_column_text(qstmt,6);
        const unsigned char *created = sqlite3_column_text(qstmt,7);
        char item[2048];
        snprintf(item, sizeof(item),
            "{\"id\":%d,\"user\":\"%s\",\"title\":\"%s\",\"type\":\"%s\",\"description\":\"%s\",\"filename\":\"%s\",\"status\":\"%s\",\"created\":\"%s\"}",
            cid, uname? (const char*)uname:"", title? (const char*)title:"", ctype? (const char*)ctype:"", desc? (const char*)desc:"", fname? (const char*)fname:"", status? (const char*)status:"", created? (const char*)created:"");
        strcat(json, item);
    }
    sqlite3_finalize(qstmt);
    strcat(json, "]}");
    return respond_json(connection, json, MHD_HTTP_OK);
}

/* POST /api/complaint - create a complaint */
static int handle_api_complaint_post(struct MHD_Connection *connection, const char *body, const char *token) {
    if (!token || strlen(token)==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"no token\"}", MHD_HTTP_UNAUTHORIZED);
    sqlite3_stmt *stmt;
    const char *sql_uid = "SELECT user_id FROM sessions WHERE token = ?;";
    if (sqlite3_prepare_v2(db, sql_uid, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED); }
    int user_id = sqlite3_column_int(stmt,0);
    sqlite3_finalize(stmt);
    char title[256]={0}, description[1024]={0}, ctype[64]={0}, filename[256]={0};
    char *b = strdup(body);
    char *p = strtok(b, "&");
    while (p) {
        if (strncmp(p, "title=",6)==0) url_decode(title, p+6);
        if (strncmp(p, "description=",12)==0) url_decode(description, p+12);
        if (strncmp(p, "type=",5)==0) url_decode(ctype, p+5);
        if (strncmp(p, "filename=",9)==0) url_decode(filename, p+9);
        p = strtok(NULL, "&");
    }
    free(b);
    if (strlen(title)==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"title required\"}", MHD_HTTP_BAD_REQUEST);
    sqlite3_stmt *ins;
    const char *sql_ins = "INSERT INTO complaints (user_id,title,type,description,filename) VALUES (?,?,?,?,?);";
    if (sqlite3_prepare_v2(db, sql_ins, -1, &ins, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_int(ins,1,user_id);
    sqlite3_bind_text(ins,2,title,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(ins,3,ctype,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(ins,4,description,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(ins,5,filename,-1,SQLITE_TRANSIENT);
    rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* POST /api/complaint/update - warden updates status */
static int handle_api_complaint_update(struct MHD_Connection *connection, const char *body, const char *token) {
    if (!token || strlen(token)==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"no token\"}", MHD_HTTP_UNAUTHORIZED);
    sqlite3_stmt *stmt;
    const char *sql_role = "SELECT users.role FROM users JOIN sessions ON users.id = sessions.user_id WHERE sessions.token = ?;";
    if (sqlite3_prepare_v2(db, sql_role, -1, &stmt, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(stmt,1,token,-1,SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"invalid token\"}", MHD_HTTP_UNAUTHORIZED); }
    const unsigned char *role = sqlite3_column_text(stmt,0);
    if (!role || strcmp((const char*)role,"warden")!=0) { sqlite3_finalize(stmt); return respond_json(connection, "{\"status\":\"error\",\"message\":\"not authorized\"}", MHD_HTTP_FORBIDDEN); }
    sqlite3_finalize(stmt);
    int id = 0;
    char status[64]={0};
    char *b = strdup(body);
    char *p = strtok(b, "&");
    while (p) {
        if (strncmp(p, "id=",3)==0) id = atoi(p+3);
        if (strncmp(p, "status=",7)==0) url_decode(status, p+7);
        p = strtok(NULL, "&");
    }
    free(b);
    if (id==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"id required\"}", MHD_HTTP_BAD_REQUEST);
    sqlite3_stmt *upd;
    const char *sql_upd = "UPDATE complaints SET status = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql_upd, -1, &upd, NULL) != SQLITE_OK) return respond_json(connection, "{\"status\":\"error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    sqlite3_bind_text(upd,1,status,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int(upd,2,id);
    rc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (rc != SQLITE_DONE) return respond_json(connection, "{\"status\":\"error\",\"message\":\"db error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* POST /upload - raw upload with X-FILENAME header, body is file bytes */
static int handle_upload(struct MHD_Connection *connection, const char *upload_filename, const void *data, size_t size) {
    if (!upload_filename || size==0) return respond_json(connection, "{\"status\":\"error\",\"message\":\"no file\"}", MHD_HTTP_BAD_REQUEST);
    /* sanitize filename: remove path separators */
    char fname[256];
    int j=0;
    for (int i=0; upload_filename[i] && j < 250; ++i) {
        if (upload_filename[i] == '/' || upload_filename[i] == '\\') continue;
        fname[j++]=upload_filename[i];
    }
    fname[j]=0;
    char path[512];
    snprintf(path, sizeof(path), "uploads/%s", fname);
    FILE *f = fopen(path, "wb");
    if (!f) return respond_json(connection, "{\"status\":\"error\",\"message\":\"cannot save\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    fwrite(data,1,size,f);
    fclose(f);
    return respond_json(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
}

/* Main connection handler */
struct connection_info_struct {
    char *post_data;
};

static int answer_to_connection(void *cls, struct MHD_Connection *connection,
                                 const char *url, const char *method,
                                 const char *version, const char *upload_data,
                                 size_t *upload_data_size, void **con_cls) {
    // Serve GET static pages
    if (strcmp(method, "GET")==0) {
        if (strcmp(url,"/")==0) return send_file(connection, "templates/index.html", "text/html");
        if (strcmp(url,"/login")==0) return send_file(connection, "templates/login.html", "text/html");
        if (strcmp(url,"/register")==0) return send_file(connection, "templates/register.html", "text/html");
        if (strcmp(url,"/student_dashboard")==0) return send_file(connection, "templates/student_dashboard.html", "text/html");
        if (strcmp(url,"/file_complaint")==0) return send_file(connection, "templates/student_complaint_form.html", "text/html");
        if (strcmp(url,"/warden_dashboard")==0) return send_file(connection, "templates/warden_dashboard.html", "text/html");
        if (strcmp(url,"/view_complaints")==0) return send_file(connection, "templates/view_complaints.html", "text/html");
        if (strcmp(url,"/complaint_details")==0) return send_file(connection, "templates/complaint_details.html", "text/html");
        if (strcmp(url,"/edit_complaint")==0) return send_file(connection, "templates/edit_complaint.html", "text/html");
        if (strcmp(url,"/about")==0) return send_file(connection, "templates/about.html", "text/html");
        if (strcmp(url,"/contact")==0) return send_file(connection, "templates/contact.html", "text/html");
        if (strncmp(url, "/static/", 8)==0) {
            char path[512];
            snprintf(path, sizeof(path), ".%s", url);
            const char *mime = "text/plain";
            if (strstr(path, ".css")) mime = "text/css";
            if (strstr(path, ".js")) mime = "application/javascript";
            if (strstr(path, ".png")) mime = "image/png";
            if (strstr(path, ".jpg")||strstr(path,".jpeg")) mime = "image/jpeg";
            if (file_exists(path)) return send_file(connection, path, mime);
        }
        if (strncmp(url, "/uploads/", 8)==0) {
            char path[512]; snprintf(path, sizeof(path), ".%s", url);
            if (file_exists(path)) return send_file(connection, path, "application/octet-stream");
        }
        if (strcmp(url, "/api/complaints")==0) {
            const char *token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
            if (!token) token = "";
            return handle_api_complaints_get(connection, token);
        }
        // Not found
        const char *nf = "Not Found";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(nf),(void*)nf,MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
        MHD_destroy_response(resp);
        return ret;
    } else if (strcmp(method, "POST")==0) {
        // Handle different POST endpoints
        if (strcmp(url, "/api/register")==0 || strcmp(url,"/api/login")==0 || strcmp(url,"/api/complaint")==0 || strcmp(url,"/api/complaint/update")==0 || strcmp(url,"/upload")==0) {
            if (*con_cls == NULL) {
                struct connection_info_struct *con_info = malloc(sizeof(struct connection_info_struct));
                con_info->post_data = calloc(1,1);
                *con_cls = (void*)con_info;
                return MHD_YES;
            }
            struct connection_info_struct *con_info = *con_cls;
            if (*upload_data_size) {
                size_t prev = strlen(con_info->post_data);
                con_info->post_data = realloc(con_info->post_data, prev + *upload_data_size + 1);
                memcpy(con_info->post_data + prev, upload_data, *upload_data_size);
                con_info->post_data[prev + *upload_data_size] = 0;
                *upload_data_size = 0;
                return MHD_YES;
            } else {
                // request completed
                const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
                const char *xfn = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-FILENAME");
                if (strcmp(url,"/api/register")==0) {
                    int ret = handle_api_register(connection, con_info->post_data);
                    free(con_info->post_data); free(con_info); *con_cls = NULL;
                    return ret;
                } else if (strcmp(url,"/api/login")==0) {
                    int ret = handle_api_login(connection, con_info->post_data);
                    free(con_info->post_data); free(con_info); *con_cls = NULL;
                    return ret;
                } else if (strcmp(url,"/api/complaint")==0) {
                    int ret = handle_api_complaint_post(connection, con_info->post_data, auth?auth:"");
                    free(con_info->post_data); free(con_info); *con_cls = NULL;
                    return ret;
                } else if (strcmp(url,"/api/complaint/update")==0) {
                    int ret = handle_api_complaint_update(connection, con_info->post_data, auth?auth:"");
                    free(con_info->post_data); free(con_info); *con_cls = NULL;
                    return ret;
                } else if (strcmp(url,"/upload")==0) {
                    // For upload, post_data contains raw bytes; save them
                    size_t size = strlen(con_info->post_data);
                    int ret = handle_upload(connection, xfn?xfn:"upload.bin", con_info->post_data, size);
                    free(con_info->post_data); free(con_info); *con_cls = NULL;
                    return ret;
                }
            }
        }
    }
    // default
    return respond_json(connection, "{\"status\":\"error\",\"message\":\"unsupported\"}", MHD_HTTP_BAD_REQUEST);
}

int main(int argc, char **argv) {
    ensure_uploads_dir();
    if (sqlite3_open("hostel.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open DB\n"); return 1;
    }
    if (init_db()) return 1;
    struct MHD_Daemon *d;
    d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                         &answer_to_connection, NULL, MHD_OPTION_END);
    if (!d) {
        fprintf(stderr, "Failed to start server\n");
        sqlite3_close(db);
        return 1;
    }
    printf("Server running on port %d\n", PORT);
    // keep running until killed by Render (SIGTERM)
    for (;;) sleep(3600);
    MHD_stop_daemon(d);
    sqlite3_close(db);
    return 0;
}
