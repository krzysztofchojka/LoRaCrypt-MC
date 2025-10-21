#include "server_commands.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Definicja bufora, jeśli nie ma jej w server_commands.h
// Można też użyć na sztywno np. 1024
#ifndef MSG_BUF
#define MSG_BUF 1024
#endif

void handle_client_message(int ser, const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *msg, size_t msg_len) {
    (void)msg_len; // nie zawsze potrzebne
    printf("[ServerThread] From %s (idx=%d): %s\n", clients[client_idx].username, client_idx, msg);

    // Prosty parser komend (np. /ping, /sayall itd.)
    if (strncmp((const char*)msg, "/ping", 5) == 0) {
        const char *reply = "PONG";
        // UWAGA: /ping nie powinien mieć prefiksu, więc jest OK
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/broadcast ", 11) == 0) {
        const char *text = (const char*)msg + 11;
        // Przekazujemy client_idx jako ID nadawcy
        send_to_all(ser, server_pk, client_idx, (const unsigned char*)text, strlen(text));
        return;
    }

    if (strncmp((const char*)msg, "/whoami", 7) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "You are %s", clients[client_idx].username);
        // Też bez prefiksu
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/help", 5) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "/ping\n/broadcast <msg>\n/whoami\n/help\n/send <idx/username> <msg>");
        // Też bez prefiksu
        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    // server_commands.c

    if (strncmp((const char*)msg, "/send ", 6) == 0) {
        int idx = -1; // Indeks odbiorcy
        int consumed = 0;
        const char *payload_start = (const char*)msg + 6;

        // --- 1. Spróbuj sparsować jako INDEKS (liczbę) ---
        if (sscanf(payload_start, "%d%n", &idx, &consumed) >= 1) {
            
            const char *msg2 = payload_start + consumed;
            while (*msg2 == ' ') msg2++; // Pomiń spacje po liczbie
            
            if (idx >= 0 && idx < client_count && *msg2) {
                // Sukces: Wysyłanie po indeksie
                char formatted_msg[MSG_BUF];
                snprintf(formatted_msg, sizeof(formatted_msg), "[%s] %s",
                         clients[client_idx].username, msg2);

                if (server_xsend_to_client(ser, server_pk, idx, (const unsigned char*)formatted_msg, strlen(formatted_msg)) == 0) {
                    printf("Sent to client %d from %s\n", idx, clients[client_idx].username);
                    // Poinformuj nadawcę o sukcesie
                    char reply[128];
                    snprintf(reply, sizeof(reply), "\nMessage sent to index %d", idx);
                    server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
                } else {
                    fprintf(stderr, "Failed to send to client %d\n", idx);
                }
            } else {
                // Błąd: Nieprawidłowy indeks lub brak wiadomości
                const char *err_msg = "Invalid index or no message";
                server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
            }

        } else {
            // --- 2. Parsowanie jako indeks się nie powiodło. Spróbuj jako NAZWĘ UŻYTKOWNIKA ---
            char target_username[64]; // Rozmiar musi pasować do client_t.username
            consumed = 0; // Zresetuj 'consumed'

            if (sscanf(payload_start, "%63s%n", target_username, &consumed) >= 1) {
                
                const char *msg2 = payload_start + consumed;
                while (*msg2 == ' ') msg2++; // Pomiń spacje po nazwie

                if (*msg2) {
                    // Mamy nazwę użytkownika ORAZ wiadomość. Znajdź pasujących klientów.
                    int sent_count = 0;
                    char formatted_msg[MSG_BUF];
                    
                    // Przygotuj sformatowaną wiadomość (z nazwą nadawcy)
                    snprintf(formatted_msg, sizeof(formatted_msg), "[%s] %s",
                             clients[client_idx].username, msg2);
                    size_t formatted_len = strlen(formatted_msg);

                    // Przejdź pętlą po WSZYSTKICH klientach
                    for (int i = 0; i < client_count; i++) {
                        // Sprawdź, czy klient jest zalogowany I czy nazwa się zgadza
                        if (clients[i].logged_in && strcmp(clients[i].username, target_username) == 0) {
                            
                            // Wyślij wiadomość
                            if (server_xsend_to_client(ser, server_pk, i, (const unsigned char*)formatted_msg, formatted_len) == 0) {
                                sent_count++;
                            } else {
                                fprintf(stderr, "Failed to send to client %d (user %s)\n", i, target_username);
                            }
                        }
                    }

                    // Poinformuj nadawcę (nadawcę, czyli client_idx) o wyniku
                    if (sent_count > 0) {
                        printf("Sent message to %d clients matching user '%s' (from %s)\n", sent_count, target_username, clients[client_idx].username);
                        // Wyślij potwierdzenie do nadawcy
                        char reply[128];
                        snprintf(reply, sizeof(reply), "\nMessage sent to %d user(s) named '%s'", sent_count, target_username);
                        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));

                    } else {
                        // Nie znaleziono użytkownika
                        const char *err_msg = "User not found or not logged in";
                        server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
                    }

                } else {
                    // Błąd: sparsowano nazwę, ale nie było po niej wiadomości
                    const char *err_msg = "Usage: /send <user_or_idx> <text>";
                    server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
                }
            
            } else {
                // --- 3. Błąd: Nie udało się sparsować ani liczby, ani nazwy ---
                const char *err_msg = "Usage: /send <user_or_idx> <text>";
                server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
            }
        }
        
        printf("loracrypt-server> "); fflush(stdout);
        return; // Ważne, aby dodać return
    }

    if (strncmp((const char*)msg, "/long", 5) == 0) {
        char reply[1024];
        snprintf(reply, sizeof(reply), "andcuhsncisnciscmoskcmosvierdnvienvierunviuen 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199");
        server_xsend_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }


    // Domyślne zachowanie (np. echo) zostało usunięte. 
    // Jeśli nic nie pasuje, wyślij informację o nieznanej komendzie.
    char reply[128];
    snprintf(reply, sizeof(reply), "Unknown command: %s. Try /help", msg);
    server_send_to_client(ser, server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
}



// ZMODYFIKOWANA Funkcja wysyłająca wiadomość do wszystkich zalogowanych klientów
void send_to_all(int ser, const unsigned char server_pk[PK_LEN],
                 int sender_idx, // DODANO: -1 dla serwera, >= 0 dla klienta
                 const unsigned char *msg, size_t msg_len) {
    
    char formatted_msg[MSG_BUF]; 
    
    // Ustal nazwę nadawcy
    const char *sender_name;
    if (sender_idx == -1) {
        sender_name = "Server";
    } else if (sender_idx >= 0 && sender_idx < client_count) {
        sender_name = clients[sender_idx].username;
    } else {
        sender_name = "Unknown"; // Sytuacja awaryjna
    }

    // Stwórz nową, sformatowaną wiadomość
    snprintf(formatted_msg, sizeof(formatted_msg), "[%s] %.*s", 
             sender_name, (int)msg_len, (const char*)msg);
    
    size_t formatted_len = strlen(formatted_msg);

    printf("[Broadcast from %s] %.*s\n", sender_name, (int)msg_len, msg);
    
    for (int i = 0; i < client_count; i++) {
        if (clients[i].logged_in) {
            
            // Opcjonalnie: nie wysyłaj broadcastu z powrotem do nadawcy
            if (i == sender_idx && 0) {
                continue;
            }
            
            // Użyj server_xsend_to_client, aby poprawnie obsłużyć długie wiadomości
            server_xsend_to_client(ser, server_pk, i, (const unsigned char*)formatted_msg, formatted_len);
        }
    }
}
