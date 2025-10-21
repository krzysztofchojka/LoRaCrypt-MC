#include "server_commands.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

// Definicja bufora, jeśli nie ma jej w server_commands.h
#ifndef MSG_BUF
#define MSG_BUF 1024
#endif

// Inicjalizacja globalnych zmiennych (jeśli są w .h jako 'extern')
struct client_t clients[MAX_CLIENTS];
int client_count = 0;

static ssize_t write_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, (const unsigned char*)buf + sent, len - sent);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += n;
    }
    return sent;
}


// Funkcja do wysłania zaszyfrowanej wiadomości od serwera do jednego klienta.
// --- ZMODYFIKOWANA SYGNATURA (usunięto serfd) ---
int server_send_to_client(const unsigned char server_pk[PK_LEN], int client_idx,
                          const unsigned char *plain, size_t plen) {
    if (client_idx < 0 || client_idx >= client_count) return -1;
    if (plen > MAX_PLAINTEXT) return -1;

    // --- POBIERZ PRAWIDŁOWY FD DLA TEGO KLIENTA ---
    int client_fd = clients[client_idx].fd;
    if (client_fd < 0) {
        fprintf(stderr, "Client %d has invalid fd (%d)\n", client_idx, client_fd);
        return -1; // Klient nie ma aktywnego FD
    }
    
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);
    unsigned char ctext[NONCE_LEN + MAX_PLAINTEXT + MAC_LEN];
    memcpy(ctext, nonce, NONCE_LEN);
    crypto_secretbox_easy(ctext + NONCE_LEN, plain, plen, nonce, clients[client_idx].tx_key);
    uint16_t flen = PK_LEN + NONCE_LEN + plen + MAC_LEN;
    unsigned char hdr[2] = { (uint8_t)(flen>>8), (uint8_t)flen };
    
    // --- WYŚLIJ DO SPECIFICZNEGO FD KLIENTA ---
    if (write_all(client_fd, hdr, 2) != 2) return -1;
    if (write_all(client_fd, server_pk, PK_LEN) != PK_LEN) return -1;
    if (write_all(client_fd, ctext, flen - PK_LEN) != flen - PK_LEN) return -1;
    
    return 0;
}

// --- ZMODYFIKOWANA SYGNATURA (usunięto serfd) ---
int server_xsend_to_client(const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *plain, size_t plen) {
    size_t offset = 0;

    while (offset < plen) {
        size_t chunk_size = plen - offset;
        if (chunk_size > MAX_PLAINTEXT) {
            chunk_size = MAX_PLAINTEXT;
        }

        // --- ZMODYFIKOWANE WYWOŁANIE ---
        if (server_send_to_client(server_pk, client_idx, plain + offset, chunk_size) != 0) {
            // Błąd zapisu (np. klient TCP się rozłączył)
            fprintf(stderr, "server_xsend failed for client %d\n", client_idx);
            return -1;
        }

        offset += chunk_size;
    }

    return 0; // success
}



// --- ZMODYFIKOWANA SYGNATURA (usunięto 'ser') ---
void handle_client_message(const unsigned char server_pk[PK_LEN],
                           int client_idx, const unsigned char *msg, size_t msg_len) {
    (void)msg_len; // nie zawsze potrzebne
    printf("[ServerThread] From %s (idx=%d, fd=%d): %s\n", 
           clients[client_idx].username, client_idx, clients[client_idx].fd, msg);

    // Prosty parser komend (np. /ping, /sayall itd.)
    if (strncmp((const char*)msg, "/ping", 5) == 0) {
        const char *reply = "PONG";
        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
        server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/broadcast ", 11) == 0) {
        const char *text = (const char*)msg + 11;
        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
        send_to_all(server_pk, client_idx, (const unsigned char*)text, strlen(text));
        return;
    }

    if (strncmp((const char*)msg, "/whoami", 7) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "You are %s", clients[client_idx].username);
        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
        server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }

    if (strncmp((const char*)msg, "/help", 5) == 0) {
        char reply[128];
        snprintf(reply, sizeof(reply), "/ping\n/broadcast <msg>\n/whoami\n/help\n/send <idx/username> <msg>");
        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
        server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }


    if (strncmp((const char*)msg, "/send ", 6) == 0) {
        int idx = -1; // Indeks odbiorcy
        int consumed = 0;
        const char *payload_start = (const char*)msg + 6;

        // --- 1. Spróbuj sparsować jako INDEKS (liczbę) ---
        if (sscanf(payload_start, "%d%n", &idx, &consumed) >= 1) {
            
            const char *msg2 = payload_start + consumed;
            while (*msg2 == ' ') msg2++; 
            
            if (idx >= 0 && idx < client_count && *msg2) {
                // Sukces: Wysyłanie po indeksie
                char formatted_msg[MSG_BUF];
                snprintf(formatted_msg, sizeof(formatted_msg), "\n[%s] %s",
                         clients[client_idx].username, msg2);

                // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                if (server_xsend_to_client(server_pk, idx, (const unsigned char*)formatted_msg, strlen(formatted_msg)) == 0) {
                    printf("Sent to client %d from %s\n", idx, clients[client_idx].username);
                    //char reply[128];
                    //snprintf(reply, sizeof(reply), "\nMessage sent to index %d", idx);
                    // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                    //server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
                } else {
                    fprintf(stderr, "Failed to send to client %d\n", idx);
                }
            } else {
                const char *err_msg = "Invalid index or no message";
                // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                server_send_to_client(server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
            }

        } else {
            // --- 2. Parsowanie jako NAZWĘ UŻYTKOWNIKA ---
            char target_username[64]; 
            consumed = 0; 

            if (sscanf(payload_start, "%63s%n", target_username, &consumed) >= 1) {
                
                const char *msg2 = payload_start + consumed;
                while (*msg2 == ' ') msg2++;

                if (*msg2) {
                    int sent_count = 0;
                    char formatted_msg[MSG_BUF];
                    
                    snprintf(formatted_msg, sizeof(formatted_msg), "\n[%s] %s",
                             clients[client_idx].username, msg2);
                    size_t formatted_len = strlen(formatted_msg);

                    for (int i = 0; i < client_count; i++) {
                        if (clients[i].logged_in && strcmp(clients[i].username, target_username) == 0) {
                            
                            // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                            if (server_xsend_to_client(server_pk, i, (const unsigned char*)formatted_msg, formatted_len) == 0) {
                                sent_count++;
                            } else {
                                fprintf(stderr, "Failed to send to client %d (user %s)\n", i, target_username);
                            }
                        }
                    }

                    if (sent_count > 0) {
                        printf("Sent message to %d clients matching user '%s' (from %s)\n", sent_count, target_username, clients[client_idx].username);
                        //char reply[128];
                        //snprintf(reply, sizeof(reply), "\nMessage sent to %d user(s) named '%s'", sent_count, target_username);
                        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                        //server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
                    } else {
                        const char *err_msg = "User not found or not logged in";
                        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                        server_send_to_client(server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
                    }

                } else {
                    const char *err_msg = "Usage: /send <user_or_idx> <text>";
                    // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                    server_send_to_client(server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
                }
            
            } else {
                const char *err_msg = "Usage: /send <user_or_idx> <text>";
                // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
                server_send_to_client(server_pk, client_idx, (const unsigned char*)err_msg, strlen(err_msg));
            }
        }
        
        printf("loracrypt-server> "); fflush(stdout);
        return; 
    }

    if (strncmp((const char*)msg, "/long", 5) == 0) {
        char reply[1024];
        snprintf(reply, sizeof(reply), "andcuhsncisnciscmoskcmosvierdnvienvierunviuen 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199");
        // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
        server_xsend_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
        return;
    }


    char reply[128];
    snprintf(reply, sizeof(reply), "Unknown command: %s. Try /help", msg);
    // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
    server_send_to_client(server_pk, client_idx, (const unsigned char*)reply, strlen(reply));
}



// --- ZMODYFIKOWANA SYGNATURA (usunięto 'ser') ---
void send_to_all(const unsigned char server_pk[PK_LEN],
                 int sender_idx, 
                 const unsigned char *msg, size_t msg_len) {
    
    char formatted_msg[MSG_BUF]; 
    
    const char *sender_name;
    if (sender_idx == -1) {
        sender_name = "Server";
    } else if (sender_idx >= 0 && sender_idx < client_count) {
        sender_name = clients[sender_idx].username;
    } else {
        sender_name = "Unknown"; 
    }

    snprintf(formatted_msg, sizeof(formatted_msg), "\n[%s] %.*s", 
             sender_name, (int)msg_len, (const char*)msg);
    
    size_t formatted_len = strlen(formatted_msg);

    printf("[Broadcast from %s] %.*s\n", sender_name, (int)msg_len, msg);
    
    for (int i = 0; i < client_count; i++) {
        // Wysyłaj tylko do zalogowanych I aktywnych (mających poprawny FD)
        if (clients[i].logged_in && clients[i].fd >= 0) {
            
            // Opcjonalnie: nie wysyłaj broadcastu z powrotem do nadawcy
            if (i == sender_idx && 0) {
                continue;
            }
            
            // --- ZMODYFIKOWANE WYWOŁANIE (bez 'ser') ---
            server_xsend_to_client(server_pk, i, (const unsigned char*)formatted_msg, formatted_len);
        }
    }
}