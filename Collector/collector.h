/**
 * collector.h
 * Header file for the Lightweight SIEM Data Collector.
 */

#ifndef COLLECTOR_H
#define COLLECTOR_H

// --- Χρώματα Τερματικού ---
#define WHITE   "\033[1;37m"
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

// --- Δομή Ρυθμίσεων Εφαρμογής (Configuration) ---
typedef struct {
    char socket_path[256];
    char auth_log[256];
    char ids_log[256];
    char root_history[256];
    char user_history[256];
} AppConfig;

#endif 