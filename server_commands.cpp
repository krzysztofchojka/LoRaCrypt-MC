#include "server_commands.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
        snprintf(reply, sizeof(reply), "/ping\n/broadcast <msg>\n/whoami\n/help");
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/long", 5) == 0) {
        char reply[1024];
        snprintf(reply, sizeof(reply), "andcuhsncisnciscmoskcmosvierdnvienvierunviuen 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199");
        server_xsend_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    // Domyślnie odsyłamy echo
    /*char reply[MAX_PLAINTEXT];
    snprintf(reply, sizeof(reply), "Echo from server: %s", msg);
    server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));*/
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
