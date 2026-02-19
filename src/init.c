#include "init.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __ANDROID__
#include <android/log.h>
#include <sys/system_properties.h>
#endif
#include "lib.h"
#include "logger.h"
#include "sock_events.h"
#include "string_builders.h"
#include "netlink_spy.h"

long conf_opt_b;
long conf_opt_c;
char *conf_opt_d;
long conf_opt_f;
long conf_opt_l;
long conf_opt_u;
long conf_opt_t;
long conf_opt_v;

char *logs_dir_path;

#ifndef __ANDROID__
FILE *_stdout;
FILE *_stderr;
#endif

static bool initialized = false;

#ifdef __ANDROID__
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
#else
static pthread_mutex_t init_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
#endif

static char *prepare_output_dir(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0777) != 0 && errno != EEXIST) {
            LOG(ERROR, "mkdir() failed for %s. %s.", path, strerror(errno));
            return NULL;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        LOG(ERROR, "Path %s exists but is not a directory.", path);
        return NULL;
    }
    
    return strdup(path);
}

static void tcpsnitch_free(void) {
        free(conf_opt_d);
        free(logs_dir_path);
#ifndef __ANDROID__
        if (_stdout) fclose(_stdout);
        if (_stderr) fclose(_stderr);
#endif
        pthread_mutex_destroy(&init_mutex);
}

#ifndef __ANDROID__
static void open_std_streams(void) {
        _stdout = my_fdopen(STDOUT_FD, "w");
        _stderr = my_fdopen(STDERR_FD, "w");
}
#endif

static void get_options(void) {
        conf_opt_b = get_long_opt_or_defaultval(OPT_B, 4096);
#ifdef __ANDROID__
        conf_opt_d = alloc_android_opt_d();
        conf_opt_u = get_long_opt_or_defaultval(OPT_U, 0);
#else
        conf_opt_c = get_long_opt_or_defaultval(OPT_C, 1);
        conf_opt_d = alloc_str_opt(OPT_D);
        
        conf_opt_u = get_long_opt_or_defaultval(OPT_U, 100000); 
#endif
        conf_opt_f = get_long_opt_or_defaultval(OPT_F, WARN);
        conf_opt_l = get_long_opt_or_defaultval(OPT_L, WARN);
        conf_opt_t = get_long_opt_or_defaultval(OPT_T, 1000);
        conf_opt_v = get_long_opt_or_defaultval(OPT_V, 0);
}

static void log_options(void) {
        LOG(INFO, "Option b: %lu.", conf_opt_b);
#ifndef __ANDROID__
        LOG(INFO, "Option c: %lu.", conf_opt_c);
#endif
        LOG(INFO, "Option d: %s", conf_opt_d);
        LOG(INFO, "Option f: %lu.", conf_opt_f);
        LOG(INFO, "Option l: %lu.", conf_opt_l);
        LOG(INFO, "Option t: %lu.", conf_opt_t);
        LOG(INFO, "Option u: %lu.", conf_opt_u);
        LOG(INFO, "Option v: %lu.", conf_opt_v);
}

static void init_logs(void) {
        char *log_file_path;
        if (!(log_file_path = alloc_concat_path(logs_dir_path, "logs.txt")))
                goto error;
        logger_init(log_file_path, conf_opt_l, conf_opt_f);
        free(log_file_path);
        return;
error:
        LOG_FUNC_ERROR;
        LOG(ERROR, "No logs to file.");
}

static void *json_dumper_thread(void *arg) {
        UNUSED(arg);
        LOG_FUNC_INFO;

        struct timespec time;
        time.tv_sec = conf_opt_t / 1000;
        time.tv_nsec = (conf_opt_t % 1000) * 1000 * 1000;

        while (true) {
                dump_all_sock_events();
                nanosleep(&time, NULL);
        }
        return NULL;
}

void start_json_dumper_thread(void) {
        pthread_t thread;
        my_pthread_create(&thread, NULL, json_dumper_thread, NULL);
}

/* Public functions */

void reset_tcpsnitch(void) {
        if (!initialized) return;
        tcpsnitch_free();
        logger_init(NULL, WARN, WARN);
        initialized = false;
        mutex_init(&init_mutex);
        sock_ev_reset();
}

void init_tcpsnitch(void) {
        mutex_lock(&init_mutex);
        if (initialized) goto exit;

#ifndef __ANDROID__
        open_std_streams();
#endif
        get_options();
        
        // SECURITY 
        if (!conf_opt_d) {
             #ifdef __ANDROID__
                 // c'est grave mais s'occup apres
             #else
                 conf_opt_d = strdup(".");
             #endif
        }

        if (conf_opt_d) {
             logs_dir_path = prepare_output_dir(conf_opt_d);
             if (!logs_dir_path) {
                  LOG(ERROR, "Failed to prepare output directory.");
                  goto exit1;
             }
             init_logs();
        } else {
             goto exit1; 
        }

        log_options();
        
        start_netlink_spy_thread();

        if (conf_opt_t) start_json_dumper_thread();
        goto exit;
exit1:
        LOG(ERROR, "TCPSnitch failed to initialize storage. Aborting capture.");
exit:
        initialized = true;
        mutex_unlock(&init_mutex);
        return;
}

__attribute__((destructor)) static void cleanup(void) {
        LOG(INFO, "Performing library cleanup before end of process.");
        dump_all_sock_events();
}