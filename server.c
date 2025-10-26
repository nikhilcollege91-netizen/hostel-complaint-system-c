#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_BUFFER 8192

sqlite3 *db;

// Utility: read file
char* read_file(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(*size);
    fread(data, 1, *size, f);
    fclose(f);
    return data;
}

// Serve file
int serve_file(struct MHD_Connection *conn, const char *path, const char *mime) {
    size_t size;
    char *data = read_file(path, &size);
    if (!data) return MHD_NO;
    struct MHD_Response *resp = MHD_create_response_from_buffer(size, data, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", mime);
    int ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

// Initialize DB
void init_db() {
    sqlite3_open("hostel.db", &db);
    char *err;
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);"
        "CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, description TEXT, file_path TEXT, status TEXT);",
        0, 0, &err);
    sqlite3_exec(db, "INSERT OR IGNORE INTO users(username,password,role) VALUES('warden','warden123','warden');", 0, 0, &err);
}

// POST login
int handle_login(struct MHD_Connection *conn, const char *data) {
    char user[64], pass[64];
    sscanf(data, "username=%63[^&]&password=%63s", user, pass);
    char sql[256];
    sprintf(sql, "SELECT role,id FROM users WHERE username='%s' AND password='%s';", user, pass);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) return MHD_NO;
    int rc = sqlite3_step(stmt);
    struct MHD_Response *resp;
    if (rc == SQLITE_ROW) {
        const unsigned char *role = sqlite3_column_text(stmt, 0);
        int uid = sqlite3_column_int(stmt, 1);
        char msg[128]; sprintf(msg, "Login success:%s:%d", role, uid);
        resp = MHD_create_response_from_buffer(strlen(msg), msg, MHD_RESPMEM_MUST_COPY);
        sqlite3_finalize(stmt);
        return MHD_queue_response(conn, MHD_HTTP_OK, resp);
    } else {
        resp = MHD_create_response_from_buffer(strlen("Invalid credentials"), "Invalid credentials", MHD_RESPMEM_PERSISTENT);
        sqlite3_finalize(stmt);
        return MHD_queue_response(conn, MHD_HTTP_UNAUTHORIZED, resp);
    }
}

// POST register
int handle_register(struct MHD_Connection *conn, const char *data) {
    char user[64], pass[64];
    sscanf(data, "username=%63[^&]&password=%63s", user, pass);
    char sql[256]; sprintf(sql, "INSERT INTO users(username,password,role) VALUES('%s','%s','student');", user, pass);
    char *err; int rc = sqlite3_exec(db, sql, 0, 0, &err);
    struct MHD_Response *resp;
    if (rc != SQLITE_OK) {
        resp = MHD_create_response_from_buffer(strlen("Registration failed"), "Registration failed", MHD_RESPMEM_PERSISTENT);
        sqlite3_free(err);
    } else {
        resp = MHD_create_response_from_buffer(strlen("Registration success"), "Registration success", MHD_RESPMEM_PERSISTENT);
    }
    return MHD_queue_response(conn, MHD_HTTP_OK, resp);
}

// POST complaint submission
int handle_complaint(struct MHD_Connection *conn, const char *data) {
    int user_id;
    char title[128], desc[512], file[128];
    sscanf(data, "user_id=%d&title=%127[^&]&description=%511[^&]&file=%127s", &user_id, title, desc, file);
    char filepath[256] = "uploads/";
    strcat(filepath, file);
    char sql[1024];
    sprintf(sql, "INSERT INTO complaints(user_id,title,description,file_path,status) VALUES(%d,'%s','%s','%s','Pending');", user_id, title, desc, filepath);
    char *err;
    sqlite3_exec(db, sql, 0, 0, &err);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen("Complaint submitted"), "Complaint submitted", MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn, MHD_HTTP_OK, resp);
}

// GET complaints listing
int handle_list(struct MHD_Connection *conn, const char *url) {
    char sql[512];
    sqlite3_stmt *stmt;
    int user_id = 0;
    int is_warden = 0;
    const char *query = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "user_id");
    const char *role = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "role");
    if (query) user_id = atoi(query);
    if (role && strcmp(role,"warden")==0) is_warden=1;
    if (is_warden)
        sprintf(sql, "SELECT id,user_id,title,description,file_path,status FROM complaints;");
    else
        sprintf(sql, "SELECT id,user_id,title,description,file_path,status FROM complaints WHERE user_id=%d;", user_id);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) return MHD_NO;
    char buffer[MAX_BUFFER]; buffer[0]=0;
    strcat(buffer,"[");
    while (sqlite3_step(stmt)==SQLITE_ROW) {
        int cid = sqlite3_column_int(stmt,0);
        int uid = sqlite3_column_int(stmt,1);
        const unsigned char *title = sqlite3_column_text(stmt,2);
        const unsigned char *desc = sqlite3_column_text(stmt,3);
        const unsigned char *filep = sqlite3_column_text(stmt,4);
        const unsigned char *status = sqlite3_column_text(stmt,5);
        char entry[1024];
        sprintf(entry,"{"id":%d,"user_id":%d,"title":"%s","description":"%s","file":"%s","status":"%s"},",cid,uid,title,desc,filep,status);
        strcat(buffer,entry);
    }
    if (strlen(buffer)>1) buffer[strlen(buffer)-1]=0;
    strcat(buffer,"]");
    sqlite3_finalize(stmt);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(buffer), buffer, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp,"Content-Type","application/json");
    return MHD_queue_response(conn, MHD_HTTP_OK, resp);
}

// POST update complaint status (warden)
int handle_update(struct MHD_Connection *conn, const char *data) {
    int cid; char status[64];
    sscanf(data,"id=%d&status=%63s",&cid,status);
    char sql[256]; sprintf(sql,"UPDATE complaints SET status='%s' WHERE id=%d;",status,cid);
    char *err;
    sqlite3_exec(db, sql, 0, 0, &err);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen("Updated"),"Updated",MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn,MHD_HTTP_OK,resp);
}

// Main handler
int answer_to_connection(void *cls, struct MHD_Connection *conn,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         size_t *upload_data_size, void **con_cls) {
    if (strcmp(method,"GET")==0) {
        if (strcmp(url,"/")==0 || strcmp(url,"/login")==0) return serve_file(conn,"templates/login.html","text/html");
        if (strcmp(url,"/register")==0) return serve_file(conn,"templates/register.html","text/html");
        if (strcmp(url,"/dashboard")==0) return serve_file(conn,"templates/dashboard.html","text/html");
        if (strncmp(url,"/static/",8)==0) {
            char path[128]; sprintf(path,"%s",url+1);
            return serve_file(conn,path,"text/css");
        }
        if (strncmp(url,"/complaints",11)==0) return handle_list(conn,url);
    }
    if (strcmp(method,"POST")==0) {
        if (strcmp(url,"/login")==0) return handle_login(conn,upload_data);
        if (strcmp(url,"/register")==0) return handle_register(conn,upload_data);
        if (strcmp(url,"/submit_complaint")==0) return handle_complaint(conn,upload_data);
        if (strcmp(url,"/update_status")==0) return handle_update(conn,upload_data);
    }
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen("Not found"),"Not found",MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(conn,MHD_HTTP_NOT_FOUND,resp);
}

// Main
int main() {
    mkdir("uploads",0777);
    init_db();
    int port = atoi(getenv("PORT")?getenv("PORT"):"10000");
    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,port,NULL,NULL,
                                                 &answer_to_connection,NULL,MHD_OPTION_END);
    if (!daemon) return 1;
    printf("Server running on port %d\n",port);
    getchar();
    MHD_stop_daemon(daemon);
    sqlite3_close(db);
    return 0;
}
