#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE "<html><head><title>Hostel Complaint System</title></head><body><h1>Server is running correctly 🎉</h1></body></html>"

int handle_request(void *cls, struct MHD_Connection *connection,
                   const char *url, const char *method,
                   const char *version, const char *upload_data,
                   size_t *upload_data_size, void **con_cls)
{
    struct MHD_Response *response;
    int ret;

    response = MHD_create_response_from_buffer(strlen(PAGE), (void *)PAGE, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

int main()
{
    const char *port_env = getenv("PORT");
    unsigned int port = port_env ? atoi(port_env) : 8080;

    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                              &handle_request, NULL, MHD_OPTION_END);

    if (daemon == NULL)
    {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("✅ Server running on port %u\n", port);
    getchar(); // keep running
    MHD_stop_daemon(daemon);
    return 0;
}
