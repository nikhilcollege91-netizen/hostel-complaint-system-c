#include <microhttpd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <openssl/sha.h>

#define DEFAULT_PORT 10000
#define UPLOAD_DIR "./uploads/"
#define DB_FILE "./hostel.db"
#define MAX_UPLOAD_SIZE (16*1024*1024) // 16 MB

// -------------------- Session Structure --------------------
struct session {
    int user_id;
    int is_warden;
    char name[128];
    char cookie[64];
    struct session *next;
};
struct session *sessions = NULL;

// -------------------- Helpers --------------------
void init_upload_dir() { mkdir(UPLOAD_DIR, 0755); }

void sha256(const char *str,char output[65]) {
    unsigned char hash[32];
    SHA256((unsigned char*)str,strlen(str),hash);
    for(int i=0;i<32;i++) sprintf(output+i*2,"%02x",hash[i]);
    output[64]=0;
}

struct session* create_session(int user_id,int is_warden,const char *name) {
    struct session *s = malloc(sizeof(struct session));
    s->user_id=user_id;
    s->is_warden=is_warden;
    strncpy(s->name,name,128);
    snprintf(s->cookie,64,"%ld",time(NULL)+rand());
    s->next = sessions;
    sessions = s;
    return s;
}

struct session* get_session_by_cookie(const char *cookie) {
    struct session *s = sessions;
    while(s){ if(strcmp(s->cookie,cookie)==0) return s; s=s->next; }
    return NULL;
}

char* read_file(const char *path) {
    FILE *f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END);
    long size = ftell(f);
    fseek(f,0,SEEK_SET);
    char *buf = malloc(size+1);
    fread(buf,1,size,f);
    fclose(f);
    buf[size]=0;
    return buf;
}

int send_text(struct MHD_Connection *conn,const char *text,int code) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(text),(void*)text,MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(conn,code,resp);
    MHD_destroy_response(resp);
    return ret;
}

// -------------------- Database Init --------------------
int init_db() {
    sqlite3 *db; char *err=0;
    if(sqlite3_open(DB_FILE,&db)!=SQLITE_OK) return 0;

    const char *users_sql =
        "CREATE TABLE IF NOT EXISTS users("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "email TEXT UNIQUE NOT NULL,"
        "password TEXT NOT NULL,"
        "is_warden INTEGER DEFAULT 0);";

    const char *complaints_sql =
        "CREATE TABLE IF NOT EXISTS complaints("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "student_id INTEGER NOT NULL,"
        "title TEXT NOT NULL,"
        "category TEXT NOT NULL,"
        "description TEXT NOT NULL,"
        "proof_file TEXT,"
        "status TEXT DEFAULT 'Pending',"
        "remark TEXT,"
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY(student_id) REFERENCES users(id));";

    sqlite3_exec(db,users_sql,0,0,&err);
    sqlite3_exec(db,complaints_sql,0,0,&err);

    // Default Warden
    sqlite3_exec(db,
        "INSERT OR IGNORE INTO users(name,email,password,is_warden) "
        "VALUES('Warden','hostelwarden.cu@gmail.com','CUWARDEN',1);",0,0,&err);

    sqlite3_close(db);
    return 1;
}

// -------------------- HTTP Handlers --------------------
int serve_file(struct MHD_Connection *conn,const char *filepath) {
    char *data = read_file(filepath);
    if(!data) return send_text(conn,"File not found",404);
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(data),(void*)data,MHD_RESPMEM_MUST_FREE);
    int ret = MHD_queue_response(conn,MHD_HTTP_OK,resp);
    MHD_destroy_response(resp);
    return ret;
}

// -------------------- POST Routes --------------------
int handle_student_register(struct MHD_Connection *conn,const char *post_data) {
    char name[128],email[128],password[128],hash[65];
    sscanf(post_data,"name=%127[^&]&email=%127[^&]&password=%127s",name,email,password);
    sha256(password,hash);

    sqlite3 *db; sqlite3_open(DB_FILE,&db);
    char sql[512]; char *err=0;
    snprintf(sql,512,"INSERT INTO users(name,email,password,is_warden) VALUES('%s','%s','%s',0);",name,email,hash);
    int rc = sqlite3_exec(db,sql,0,0,&err);
    sqlite3_close(db);
    if(rc!=SQLITE_OK) return send_text(conn,"Email already exists",400);
    return send_text(conn,"Registration Successful",200);
}

int handle_student_login(struct MHD_Connection *conn,const char *post_data) {
    char email[128],password[128],hash[65];
    sscanf(post_data,"email=%127[^&]&password=%127s",email,password);
    sha256(password,hash);

    sqlite3 *db; sqlite3_open(DB_FILE,&db);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,"SELECT id,name,password FROM users WHERE email=? AND is_warden=0;",-1,&stmt,0);
    sqlite3_bind_text(stmt,1,email,-1,SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if(rc==SQLITE_ROW){
        const char *db_pass = (const char*)sqlite3_column_text(stmt,2);
        if(strcmp(db_pass,hash)==0){
            int uid = sqlite3_column_int(stmt,0);
            const char *uname = (const char*)sqlite3_column_text(stmt,1);
            struct session *s = create_session(uid,0,uname);
            sqlite3_finalize(stmt); sqlite3_close(db);

            struct MHD_Response *resp = MHD_create_response_from_buffer(strlen("Login Successful"),"Login Successful",MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp,"Set-Cookie",s->cookie);
            int ret = MHD_queue_response(conn,MHD_HTTP_OK,resp);
            MHD_destroy_response(resp);
            return ret;
        }
    }
    sqlite3_finalize(stmt); sqlite3_close(db);
    return send_text(conn,"Invalid email or password",401);
}

// -------------------- Main HTTP Handler --------------------
int handle_connection(void *cls, struct MHD_Connection *conn,const char *url,const char *method,
    const char *ver,const char *upload_data, size_t *upload_data_size, void **con_cls) {

    if(strcmp(method,"GET")==0){
        if(strcmp(url,"/")==0) return serve_file(conn,"templates/index.html");
        else if(strcmp(url,"/student/login")==0) return serve_file(conn,"templates/student_login.html");
        else if(strcmp(url,"/student/register")==0) return serve_file(conn,"templates/student_register.html");
        else if(strcmp(url,"/warden/login")==0) return serve_file(conn,"templates/warden_login.html");
        else return send_text(conn,"404 Not Found",404);
    }

    if(strcmp(method,"POST")==0){
        const char *post_data = MHD_lookup_connection_value(conn,MHD_POSTDATA_KIND,NULL);
        if(strcmp(url,"/student/register")==0) return handle_student_register(conn,post_data);
        else if(strcmp(url,"/student/login")==0) return handle_student_login(conn,post_data);
        else return send_text(conn,"POST route not implemented",501);
    }

    return send_text(conn,"Method Not Allowed",405);
}

// -------------------- Main --------------------
int main() {
    srand(time(NULL));
    init_upload_dir();
    init_db();

    int port = DEFAULT_PORT;
    const char *env_port = getenv("PORT");
    if(env_port) port = atoi(env_port);

    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,port,NULL,NULL,
        &handle_connection,NULL,MHD_OPTION_END);
    if(!daemon) return 1;

    printf("Server running on port %d\n",port);
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
