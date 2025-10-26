
#ifndef COMPLAINTS_H
#define COMPLAINTS_H

int init_db(const char *db_path);
int add_complaint(const char *db_path, int student_id, const char *title, const char *category, const char *description, const char *proof_file);
int update_status(const char *db_path, int complaint_id, const char *status);
int add_remark(const char *db_path, int complaint_id, const char *remark);
char* get_complaints_json_for_student(const char *db_path, int student_id);
int list_complaints_count(const char *db_path);
int close_lib();

#endif
