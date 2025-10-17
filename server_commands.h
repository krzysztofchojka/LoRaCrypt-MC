#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PK_LEN 32
#define SESSION_KEY_LEN 32
#define MAX_PLAINTEXT 192

// deklaracja struktury klienta
struct client_t {
    unsigned char pk[PK_LEN];
    unsigned char rx_key[SESSION_KEY_LEN];
    unsigned char tx_key[SESSION_KEY_LEN];
    int logged_in;
    char username[64];
};

// globalne zmienne z loracrypt.c / loracrypt.cpp
extern int client_count;
extern struct client_t clients[];

// deklaracja funkcji z loracrypt.c
int server_send_to_client(int serfd, const unsigned char server_pk[PK_LEN], int client_idx,
                          const unsigned char *plain, size_t plen);

// Typ funkcji komendy
typedef void (*command_func_t)(int ser, const unsigned char server_pk[PK_LEN], int client_idx,
                               const unsigned char *args, size_t args_len);

// Struktura komendy
typedef struct {
    const char *name;          // np. "/ping"
    command_func_t handler;    // funkcja obsługi
    const char *description;   // opis dla /help
} command_t;

// Główna funkcja obsługi wiadomości
void handle_client_message(int ser, const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *msg, size_t msg_len);

// Wysyłka do wszystkich zalogowanych
void send_to_all(int ser, const unsigned char server_pk[PK_LEN],
                 const unsigned char *msg, size_t msg_len);

#ifdef __cplusplus
} // extern "C"
#endif
