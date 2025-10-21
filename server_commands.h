#ifndef SERVER_COMMANDS_H
#define SERVER_COMMANDS_H

#include <stddef.h> // dla size_t
#include <stdint.h>
#include <sodium.h> // dla typów kluczy

// --- Stałe przeniesione tutaj, aby były widoczne wszędzie ---
#define PK_LEN crypto_kx_PUBLICKEYBYTES // 32
#define SK_LEN crypto_kx_SECRETKEYBYTES // 32
#define SESSION_KEY_LEN crypto_kx_SESSIONKEYBYTES // 32
#define NONCE_LEN crypto_secretbox_NONCEBYTES // 24
#define MAC_LEN crypto_secretbox_MACBYTES // 16

#define MAX_FRAME 240
#define MAX_PLAINTEXT (MAX_FRAME - NONCE_LEN - MAC_LEN - PK_LEN)

#define MAX_CLIENTS 32
#define MSG_BUF 1024 // Maksymalna długość wiadomości

// --- NOWY ENUM ---
enum client_type { CLIENT_LORA, CLIENT_TCP };

// --- ZMODYFIKOWANA STRUKTURA ---
struct client_t {
    unsigned char pk[PK_LEN];
    unsigned char rx_key[SESSION_KEY_LEN];
    unsigned char tx_key[SESSION_KEY_LEN];
    int logged_in;
    char username[64];
    int fd; // Deskryptor pliku (serial lub socket)
    enum client_type type; // Typ klienta
};

// Deklaracje globalnych zmiennych (zostaną zdefiniowane w server_commands.c)
extern struct client_t clients[MAX_CLIENTS];
extern int client_count;


// --- ZMODYFIKOWANE DEKLARACJE FUNKCJI (usunięto 'ser' / 'serfd') ---

/**
 * @brief Wysyła zaszyfrowaną wiadomość do jednego klienta (wiele ramek jeśli trzeba).
 */
int server_xsend_to_client(const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *plain, size_t plen);

/**
 * @brief Wysyła pojedynczą zaszyfrowaną ramkę do klienta.
 */
int server_send_to_client(const unsigned char server_pk[PK_LEN], int client_idx,
                          const unsigned char *plain, size_t plen);


/**
 * @brief Przetwarza wiadomość tekstową od zalogowanego klienta.
 */
void handle_client_message(const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *msg, size_t msg_len);

/**
 * @brief Wysyła wiadomość do wszystkich zalogowanych klientów.
 */
void send_to_all(const unsigned char server_pk[PK_LEN],
                 int sender_idx, // -1 dla serwera, >= 0 dla klienta
                 const unsigned char *msg, size_t msg_len);

#endif // SERVER_COMMANDS_H