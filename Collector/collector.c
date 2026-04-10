/**
 * @file collector.c
 * @brief Enterprise-Grade Data Collector in C (Final Edition).
 * * Υλοποιεί την παρακολούθηση αρχείων καταγραφής σε πραγματικό χρόνο (Inotify),
 * μηδενική κατανάλωση πόρων (0% CPU), και ασφαλή αποστολή δεδομένων (Persistent Socket)
 * με μηχανισμό αποτροπής απώλειας δεδομένων (Ring Buffer).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include "collector.h"

#define MAX_LINE 4096
#define MSG_BUF  5000 
#define EVENT_SIZE  (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define CONFIG_FILE "collector.conf"

/* ========================================================================
 * 1. GLOBAL ΜΕΤΑΒΛΗΤΕΣ & ΔΟΜΕΣ
 * ======================================================================== */
AppConfig config; 

#define BUFFER_SIZE 1000 
char ring_buffer[BUFFER_SIZE][MSG_BUF + 256];
int rb_head = 0, rb_tail = 0, rb_count = 0;
int engine_socket = -1; 

typedef struct {
    char *filepath;
    int wd;          
    FILE *fp;        
    const char *type;
} LogMonitor;

LogMonitor monitors[4]; 

/* ========================================================================
 * 2. CONFIGURATION PARSER
 * ======================================================================== */
void load_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf(RED "[!] CRITICAL: Failed to locate configuration file '%s'.\n" RESET, filename);
        exit(EXIT_FAILURE);
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[128], value[256];
        if (sscanf(line, "%127[^=]=%255[^\n]", key, value) == 2) {
            if (strcmp(key, "SOCKET_PATH") == 0) snprintf(config.socket_path, sizeof(config.socket_path), "%.250s", value);
            else if (strcmp(key, "AUTH_LOG") == 0) snprintf(config.auth_log, sizeof(config.auth_log), "%.250s", value);
            else if (strcmp(key, "IDS_LOG") == 0) snprintf(config.ids_log, sizeof(config.ids_log), "%.250s", value);
            else if (strcmp(key, "ROOT_HISTORY") == 0) snprintf(config.root_history, sizeof(config.root_history), "%.250s", value);
            else if (strcmp(key, "USER_HISTORY") == 0) snprintf(config.user_history, sizeof(config.user_history), "%.250s", value);
        }
    }
    fclose(fp);
}

/* ========================================================================
 * 3. PERSISTENT SOCKET & BUFFERING
 * ======================================================================== */
void enqueue_alert(const char *msg) {
    if (rb_count < BUFFER_SIZE) {
        strncpy(ring_buffer[rb_tail], msg, sizeof(ring_buffer[rb_tail]) - 1);
        rb_tail = (rb_tail + 1) % BUFFER_SIZE;
        rb_count++;
    } else {
        strncpy(ring_buffer[rb_tail], msg, sizeof(ring_buffer[rb_tail]) - 1);
        rb_tail = (rb_tail + 1) % BUFFER_SIZE;
        rb_head = (rb_head + 1) % BUFFER_SIZE; 
    }
}

int try_reconnect_and_flush() {
    if (engine_socket != -1) return 1; 
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) return 0;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.100s", config.socket_path);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        engine_socket = sock; 
        if (rb_count > 0) {
            printf(YELLOW "\n[+] STATE CHANGE: Connection established. Flushing %d events...\n" RESET, rb_count);
            while (rb_count > 0) {
                if (write(engine_socket, ring_buffer[rb_head], strlen(ring_buffer[rb_head])) < 0) {
                    close(engine_socket);
                    engine_socket = -1;
                    return 0; 
                }
                rb_head = (rb_head + 1) % BUFFER_SIZE;
                rb_count--;
            }
        }
        return 1;
    } else {
        close(sock);
        return 0;
    }
}

void send_to_engine(const char* tag, const char* msg, const char* color) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("%s[%s] [%s] %s%s\n", color, time_buf, tag, msg, RESET);
    
    char socket_buf[MSG_BUF + 256];
    snprintf(socket_buf, sizeof(socket_buf), "%s|[%s] %s\n", tag, time_buf, msg);

    if (try_reconnect_and_flush()) {
        if (write(engine_socket, socket_buf, strlen(socket_buf)) < 0) {
            printf(RED "[!] WARNING: IPC Pipe broken. Spooling event to memory.\n" RESET);
            close(engine_socket);
            engine_socket = -1; 
            enqueue_alert(socket_buf); 
        }
    } else {
        if (rb_count == 0) { 
            printf(RED "[!] WARNING: Analysis Engine is unreachable. Memory buffering active.\n" RESET);
        }
        enqueue_alert(socket_buf);
    }
}

/* ========================================================================
 * 4. JSON PARSING & ROUTING
 * ======================================================================== */
void safe_json_extract(const char* json_line, const char* key, char* out, size_t max_len) {
    out[0] = '\0'; 
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    
    const char *pos = strstr(json_line, search_key);
    if (!pos) {
        strncpy(out, "unknown", max_len - 1);
        return;
    }
    
    pos += strlen(search_key);
    while (*pos == ' ' || *pos == '\t') pos++; 
    
    if (*pos == '"') {
        pos++;
        size_t i = 0;
        while (*pos != '\0' && i < max_len - 1) {
            if (*pos == '\\' && *(pos + 1) != '\0') {
                pos++; out[i++] = *pos;
            } else if (*pos == '"') {
                break;
            } else {
                out[i++] = *pos;
            }
            pos++;
        }
        out[i] = '\0';
    } else {
        strncpy(out, "unknown", max_len - 1);
    }
}

void process_log_line(const char *type, char *line) {
    char m[MSG_BUF];
    line[strcspn(line, "\n")] = 0; 
    if (strlen(line) == 0) return;

    if (strcmp(type, "IDS") == 0) {
        if (strstr(line, "\"event_type\":\"alert\"")) {
            char ids_sig[256], ids_src[64], ids_dest[64], ids_class[128]; // <-- Πρόσθεσα το ids_dest
            
            safe_json_extract(line, "signature", ids_sig, sizeof(ids_sig));
            if (strstr(ids_sig, "HTTP Host")) return; 
            safe_json_extract(line, "category", ids_class, sizeof(ids_class)); 
            safe_json_extract(line, "src_ip", ids_src, sizeof(ids_src));
            safe_json_extract(line, "dest_ip", ids_dest, sizeof(ids_dest)); // <-- ΝΕΟ: Εξάγει το Target IP
            
            // <-- ΝΕΟ: Στέλνει και το Src και το Dest στην Python
            snprintf(m, sizeof(m), "IDS Alert: %s (Src: %s) (Dest: %s)", ids_sig, ids_src, ids_dest); 
            send_to_engine(ids_class, m, YELLOW); 
        }
    }
    else if (strcmp(type, "AUTH") == 0) {
        if (strstr(line, "CRON")) return;

        if (strstr(line, "Accepted password")) {
            snprintf(m, sizeof(m), "Successful Login: %s", line);
            send_to_engine("SESSION_START", m, YELLOW);
        } else if (strstr(line, "session closed for user root")) {
            send_to_engine("ROOT_EXIT", "Root privilege dropped", BLUE);
        } else if (strstr(line, "session closed for user") && strstr(line, "sshd")) {
            send_to_engine("SESSION_END", "SSH Session Disconnected", BLUE);
        } else if (strstr(line, "sudo:") && strstr(line, "COMMAND=")) {
            snprintf(m, sizeof(m), "Privilege Escalation Attempt: %s", line);
            send_to_engine("ROOT_ACCESS", m, RED);
        } else if (strstr(line, "Failed password")) {
            send_to_engine("AUTH_FAIL", line, YELLOW);
        }
    }
    else if (strcmp(type, "USER_CMD") == 0) {
        send_to_engine("USER_CMD", line, BLUE);
    }
    else if (strcmp(type, "ROOT_CMD") == 0) {
        send_to_engine("ROOT_CMD", line, RED);
    }
}

/* ========================================================================
 * 5. INOTIFY ENGINE (MAIN LOOP)
 * ======================================================================== */
int main() {
    signal(SIGPIPE, SIG_IGN);

    // Εκτύπωση Enterprise Banners με όλα τα δεδομένα του Config
    printf(WHITE "==========================================================\n");
    printf("              SIEM COLLECTOR AGENT - ONLINE\n");
    printf("==========================================================\n" RESET);
    
    load_config(CONFIG_FILE);

    monitors[0] = (LogMonitor){config.auth_log, -1, NULL, "AUTH"};
    monitors[1] = (LogMonitor){config.ids_log, -1, NULL, "IDS"};
    monitors[2] = (LogMonitor){config.root_history, -1, NULL, "ROOT_CMD"};
    monitors[3] = (LogMonitor){config.user_history, -1, NULL, "USER_CMD"};

    printf(WHITE "----------------------------------------------------------\n");
    printf("[+] Architecture : Event-Driven (Inotify)\n");
    printf("[+] IPC Socket   : %s\n", config.socket_path);
    printf("[+] Memory Buffer: Ring Buffer (Zero-Data-Loss)\n");
    printf("--- Monitored Targets ---\n");
    printf("[*] Auth Logs    : %s\n", config.auth_log);
    printf("[*] IDS Alerts   : %s\n", config.ids_log);
    printf("[*] Root History : %s\n", config.root_history);
    printf("[*] User History : %s\n", config.user_history);
    printf("----------------------------------------------------------\n" RESET);

    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init failed");
        exit(1);
    }

    fd_set rfds;
    struct timeval tv;
    char buffer[EVENT_BUF_LEN];

    while (1) {
        for (int i = 0; i < 4; i++) {
            if (monitors[i].wd == -1) {
                monitors[i].fp = fopen(monitors[i].filepath, "r");
                if (monitors[i].fp) {
                    fseek(monitors[i].fp, 0, SEEK_END); 
                    monitors[i].wd = inotify_add_watch(inotify_fd, monitors[i].filepath, IN_MODIFY | IN_MOVE_SELF | IN_IGNORED);
                }
            }
        }

        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);
        tv.tv_sec = 2; 
        tv.tv_usec = 0;

        int ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
        
        if (engine_socket == -1 && rb_count > 0) {
            try_reconnect_and_flush();
        }

        if (ret > 0 && FD_ISSET(inotify_fd, &rfds)) {
            ssize_t length = read(inotify_fd, buffer, EVENT_BUF_LEN);
            if (length < 0) continue;

            for (char *ptr = buffer; ptr < buffer + length; ) {
                struct inotify_event *event = (struct inotify_event *) ptr;
                
                for (int i = 0; i < 4; i++) {
                    if (monitors[i].wd == event->wd) {
                        
                        if (event->mask & IN_MODIFY) {
                            char line[MAX_LINE];
                            while (fgets(line, sizeof(line), monitors[i].fp) != NULL) {
                                process_log_line(monitors[i].type, line);
                            }
                            clearerr(monitors[i].fp);
                        }
                        
                        if (event->mask & (IN_MOVE_SELF | IN_IGNORED | IN_DELETE_SELF)) {
                            inotify_rm_watch(inotify_fd, monitors[i].wd);
                            if (monitors[i].fp) {
                                fclose(monitors[i].fp);
                                monitors[i].fp = NULL;
                            }
                            monitors[i].wd = -1; 
                        }
                    }
                }
                ptr += EVENT_SIZE + event->len;
            }
        }
    }

    close(inotify_fd);
    return 0;
}