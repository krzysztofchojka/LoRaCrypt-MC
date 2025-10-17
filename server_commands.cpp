#include "server_commands.h"
#include <stdio.h>
#include <string.h>

// Obsługa komend od zalogowanych klientów
void handle_client_message(int ser, const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *msg, size_t msg_len) {
    (void)msg_len; // nie zawsze potrzebne
    printf("[ServerThread] From %s (idx=%d): %s\n", clients[client_idx].username, client_idx, msg);

    // Prosty parser komend (np. /ping, /sayall itd.)
    if (strncmp((const char*)msg, "/ping", 5) == 0) {
        const char *reply = "PONG";
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/broadcast ", 11) == 0) {
        const char *text = (const char*)msg + 11;
        send_to_all(ser, server_pk, (const unsigned char*)text, strlen(text));
        return;
    }

    if (strncmp((const char*)msg, "/whoami", 7) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "You are %s", clients[client_idx].username);
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/help", 5) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "\n/ping\n/broadcast <msg>\n/whoami\n/help");
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    // Domyślnie odsyłamy echo
    char reply[MAX_PLAINTEXT];
    snprintf(reply, sizeof(reply), "Echo from server: %s", msg);
    server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
}

// Funkcja wysyłająca wiadomość do wszystkich zalogowanych klientów
void send_to_all(int ser, const unsigned char server_pk[PK_LEN],
                 const unsigned char *msg, size_t msg_len) {
    printf("[Broadcast] %.*s\n", (int)msg_len, msg);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].logged_in) {
            server_send_to_client(ser, server_pk, i, msg, msg_len);
        }
    }
}
