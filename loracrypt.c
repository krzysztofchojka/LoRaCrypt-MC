// loracrypt.c
// Multi-client LoRa+UART+TCP with libsodium (NON-BLOCKING SERVER/CLIENT)
// gcc loracrypt.c server_commands.c -o loracrypt -lsodium -lncurses

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/select.h>
#include <stdint.h>
#include <sodium.h>
#include <ctype.h>
#include "server_commands.h"
#include <ncurses.h>
#include <sys/time.h>
#include <time.h>

// --- INCLUDY SIECIOWE ---
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
// ------------------------------

#define NONCE_LEN crypto_secretbox_NONCEBYTES // 24
#define MAC_LEN crypto_secretbox_MACBYTES // 16
#define KEY_LEN crypto_secretbox_KEYBYTES // 32

#define MAX_FRAME 240
#define HELLO_MSG "HELLO test123"
#define HELLO_LEN (sizeof(HELLO_MSG)-1)
#define HANDSHAKE_HDR 0xFFFF
#define MAX_CLIENTS 32
//#define BAUDRATE B115200

#define MAX_HISTORY 100

// for ncurses
#define MAX_IN 512 // bufor wejściowy
#define MSG_BUF 1024 // maks. długość wiadomości przychodzącej (już w server_commands.h)
// Maksymalny rozmiar bufora wejściowego dla pojedynczego połączenia (TCP lub LoRa)
#define MAX_CONN_BUFFER (MAX_FRAME * 2) 

int BAUDRATE = B115200;

struct timeval ping_start;
int waiting_for_pong = 0;

// Sprawdza dane logowania z users.json
int check_credentials(const char *login, const char *password) {
    FILE *f = fopen("users.json", "r");
    if (!f) {
        perror("users.json");
        return 0;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char ulogin[64], upass[64];
        if (sscanf(line, " { \"login\": \"%63[^\"]\", \"password\": \"%63[^\"]\"", ulogin, upass) == 2) {
            if (strcmp(ulogin, login) == 0 && strcmp(upass, password) == 0) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

// funkcja trim: usuwa spacje z początku i końca
char* trim(char* str) {
    while(*str && isspace(*str)) str++;      // usuń spacje z przodu
    if(*str == 0) return str;
    char* end = str + strlen(str) - 1;
    while(end > str && isspace(*end)) end--; // usuń spacje z tyłu
    *(end+1) = 0;
    return str;
}

// Otwórz UART
int open_serial(const char *dev) {
    int fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        perror("open_serial");
        exit(1);
    }
    struct termios tio;
    tcgetattr(fd, &tio);
    cfmakeraw(&tio);
    cfsetispeed(&tio, BAUDRATE);
    cfsetospeed(&tio, BAUDRATE);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tcsetattr(fd, TCSANOW, &tio);
    printf("Serial port %s opened (fd %d)\n", dev, fd);
    return fd;
}

// --- NOWE FUNKCJE SIECIOWE ---
// (Funkcje open_server_socket, open_client_socket, is_network_address bez zmian)

int is_network_address(const char *dev, char *ip_buf, size_t ip_buf_len, int *port_buf) {
    char *colon = strrchr(dev, ':');
    if (!colon) return 0; 
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return 0; 
    if (strchr(dev, '/') != NULL) return 0; 
    if (colon == dev) return 0;
    size_t ip_len = colon - dev;
    if (ip_len >= ip_buf_len) return 0; 
    memcpy(ip_buf, dev, ip_len);
    ip_buf[ip_len] = '\0';
    *port_buf = port;
    return 1;
}

int open_server_socket(const char *ip, int port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }
    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (strcmp(ip, "0.0.0.0") == 0) {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(ip);
        if (he == NULL) { herror("gethostbyname"); exit(1); }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(listen_fd, 10) < 0) { perror("listen"); exit(1); }
    printf("Server listening on %s:%d (fd %d)\n", ip, port, listen_fd);
    return listen_fd;
}

int open_client_socket(const char *ip, int port) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("socket"); exit(1); }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(ip);
        if (he == NULL) { herror("gethostbyname"); fprintf(stderr, "Could not resolve hostname: %s\n", ip); exit(1); }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
        printf("Resolved %s to %s\n", ip, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    }
    if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); exit(1);
    }
    printf("Connected to %s:%d (fd %d)\n", ip, port, sock_fd);
    return sock_fd;
}
// ------------------------------


// Ta funkcja jest używana TYLKO przez klienta (do logowania) i do zapisu.
// Główna pętla serwera i klienta NIE UŻYWA jej do odczytu.
ssize_t read_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, (unsigned char*)buf + total, len - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // To jest OK tylko dla sekwencji blokującej (login klienta)
                usleep(10000); 
                continue;
            }
            return -1; // Prawdziwy błąd odczytu
        }
        if (r == 0) {
            // EOF - druga strona zamknęła połączenie
            return 0; 
        }
        total += r;
    }
    return total;
}

// Dokładnie zapisuje len bajtów
ssize_t write_all(int fd, const void *buf, size_t len) {
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

// Używamy globalnej tablicy zdefiniowanej w server_commands.h
extern struct client_t clients[MAX_CLIENTS];
extern int client_count;

// Dodaj klienta (jeśli nie ma) i zwróć indeks lub -1
// --- ZMODYFIKOWANA --- (Usunięto `input_buffer_len`)
int add_client(const unsigned char client_pk[PK_LEN],
               const unsigned char server_pk[PK_LEN], const unsigned char server_sk[SK_LEN],
               int fd, enum client_type type) {
    // sprawdź czy już istnieje
    for (int i = 0; i < client_count; ++i) {
        if (memcmp(clients[i].pk, client_pk, PK_LEN) == 0) {
            // Klient już istnieje, zaktualizujmy jego FD i typ
            clients[i].fd = fd;
            clients[i].type = type;
            // (Usunięto zerowanie bufora - bufor jest teraz powiązany z fd, nie z client_t)
            printf("Client %d re-authenticated (fd=%d, type=%d)\n", i, fd, type);
            return i;
        }
    }
    if (client_count >= MAX_CLIENTS) return -1;

    int idx = client_count; // Nowy indeks
    memcpy(clients[idx].pk, client_pk, PK_LEN);
    clients[idx].fd = fd; 
    clients[idx].type = type; 
    clients[idx].logged_in = 0; 
    memset(clients[idx].username, 0, sizeof(clients[idx].username));
    // (Usunięto zerowanie bufora)

    // wylicz sesyjne klucze (server role)
    if (crypto_kx_server_session_keys(clients[idx].rx_key, clients[idx].tx_key,
            server_pk, server_sk, client_pk) != 0) {
        fprintf(stderr, "crypto_kx_server_session_keys failed for new client\n");
        return -1;
    }
    
    client_count++; // Zwiększ liczbę klientów
    printf("New client added idx=%d fd=%d type=%d pk=", idx, fd, type);
    for (int i=0;i<PK_LEN;i++) printf("%02x", client_pk[i]);
    printf("\n");
    return idx;
}

// Znajdź index klienta po pk (NULL -> -1)
int find_client_by_pk(const unsigned char pk[PK_LEN]) {
    for (int i = 0; i < client_count; ++i) {
        if (memcmp(clients[i].pk, pk, PK_LEN) == 0) return i;
    }
    return -1;
}

// HANDSHAKE (klient) - bez zmian
void handshake_client(int ser,
    unsigned char my_pk[PK_LEN], unsigned char my_sk[SK_LEN],
    unsigned char server_pk[PK_LEN],
    unsigned char rx_key[SESSION_KEY_LEN], unsigned char tx_key[SESSION_KEY_LEN]) {

    if (crypto_kx_keypair(my_pk, my_sk) != 0) {
        fprintf(stderr, "crypto_kx_keypair failed\n"); exit(1);
    }

    uint16_t hh = HANDSHAKE_HDR;
    unsigned char hh_buf[2] = { (uint8_t)(hh>>8), (uint8_t)hh };
    if (write_all(ser, hh_buf, 2) != 2) { fprintf(stderr, "Sending handshake hdr failed\n"); exit(1); }
    if (write_all(ser, HELLO_MSG, HELLO_LEN) != HELLO_LEN) { fprintf(stderr, "Sending HELLO failed\n"); exit(1); }
    if (write_all(ser, my_pk, PK_LEN) != PK_LEN) { fprintf(stderr, "Sending client PK failed\n"); exit(1); }
    printf("Wysłano handshake (HELLO + client PK) do serwera\n");

    if (read_all(ser, server_pk, PK_LEN) != PK_LEN) { fprintf(stderr, "Reading server PK failed\n"); exit(1); }
    printf("Odebrano PK serwera\n");

    if (crypto_kx_client_session_keys(rx_key, tx_key, my_pk, my_sk, server_pk) != 0) {
        fprintf(stderr, "crypto_kx_client_session_keys failed\n"); exit(1);
    }
    printf("Session keys computed (client)\n");
}


// ------------------------------------------------------------------
// --- NOWA LOGIKA SERWERA (ZASTĘPUJE handle_data_from_fd) ---
// ------------------------------------------------------------------

/**
 * @brief Przetwarza dane zgromadzone w buforze (TCP lub LoRa).
 * Szuka kompletnych pakietów (handshake lub danych),
 * przetwarza je i usuwa z bufora.
 * @param buffer Wskaźnik do bufora danych (np. lora_buffer lub conn->buffer)
 * @param buffer_len Wskaźnik do długości danych w buforze (zostanie zaktualizowany)
 * @param fd Deskryptor pliku, z którego dane pochodzą (dla logowania i wysyłania odp.)
 * @param type Typ połączenia (CLIENT_LORA lub CLIENT_TCP)
 * @param server_pk Klucz publiczny serwera
 * @param server_sk Klucz prywatny serwera
 */
void process_data_buffer(unsigned char *buffer, size_t *buffer_len, int fd, enum client_type type,
                         const unsigned char server_pk[PK_LEN], const unsigned char server_sk[SK_LEN]) 
{
    // Pętla przetwarzająca wszystkie kompletne pakiety znalezione w buforze
    while (1) {
        
        // --- KROK 1: Sprawdź, czy mamy wystarczająco danych na nagłówek ---
        if (*buffer_len < 2) {
            // Za mało danych nawet na nagłówek, wyjdź i czekaj na resztę
            return;
        }
        
        uint16_t flen = ((uint16_t)buffer[0] << 8) | buffer[1];
        size_t total_packet_len = 0;
        
        // --- KROK 2: Ustal oczekiwaną długość pakietu ---
        if (flen == HANDSHAKE_HDR) {
            // --- PRZYPADEK HANDSHAKE ---
            total_packet_len = 2 + HELLO_LEN + PK_LEN;

            // Sprawdź, czy mamy cały pakiet w buforze
            if (*buffer_len < total_packet_len) {
                return; // Niekompletny, czekaj
            }

            // Mamy kompletny pakiet handshake. Przetwórz go.
            unsigned char *hello = buffer + 2;
            unsigned char *client_pk = buffer + 2 + HELLO_LEN;

            if (strncmp((char*)hello, HELLO_MSG, HELLO_LEN) != 0) {
                fprintf(stderr, "Bad HELLO content during handshake on fd %d\n", fd);
            } else {
                // Wyślij odpowiedź (Server PK)
                if (write_all(fd, server_pk, PK_LEN) != PK_LEN) {
                    fprintf(stderr, "Sending server PK failed in handshake on fd %d\n", fd);
                } else {
                    // Zarejestruj klienta
                    int idx = add_client(client_pk, server_pk, server_sk, fd, type);
                    if (idx < 0) {
                        fprintf(stderr, "Failed to add client (limit?) from fd %d\n", fd);
                    } else {
                        printf("Handshake complete for fd %d, client idx=%d\n", fd, idx);
                    }
                }
            }
            printf("loracrypt-server> "); fflush(stdout);

        } else {
            // --- PRZYPADEK PAKIETU DANYCH ---
            
            // *** KRYTYCZNA POPRAWKA ***
            // Sprawdź poprawność długości, ZANIM spróbujesz czytać
            if (flen == 0 || flen > MAX_FRAME || flen < PK_LEN + NONCE_LEN + MAC_LEN) {
                fprintf(stderr, "Frame invalid len (%u) on fd %d, discarding ENTIRE buffer to resync\n", flen, fd);
                // To jest desynchronizacja. Najbezpieczniej jest wyczyścić cały bufor.
                *buffer_len = 0; 
                return; // Zakończ przetwarzanie, czekaj na nowe, czyste dane
            }

            total_packet_len = 2 + flen;

            // Sprawdź, czy mamy cały pakiet w buforze
            if (*buffer_len < total_packet_len) {
                // Mamy nagłówek, ale pakiet jest niekompletny
                return; // Wyjdź i czekaj na resztę danych
            }

            // Mamy kompletny pakiet danych. Przetwórz go.
            unsigned char *sender_pk = buffer + 2;
            unsigned char *enc_buf = buffer + 2 + PK_LEN; // (nonce + cipher)
            size_t enc_len = flen - PK_LEN;
            
            int idx = find_client_by_pk(sender_pk);
            if (idx < 0) {
                fprintf(stderr, "Unknown sender pk from fd %d, ignoring (run handshake)\n", fd);
            
            } else {
                // Mamy klienta. Zaktualizujmy jego FD i typ.
                if (clients[idx].fd != fd) {
                     printf("Client %d (%s) FD updated from %d to %d (type %d)\n", 
                            idx, clients[idx].username, clients[idx].fd, fd, type);
                }
                clients[idx].fd = fd;
                clients[idx].type = type;

                // --- ODSZYFROWYWANIE ---
                unsigned char *nonce = enc_buf;
                unsigned char *cipher = enc_buf + NONCE_LEN;
                size_t clen = enc_len - NONCE_LEN;
                unsigned char plain[MAX_PLAINTEXT+1];
                
                if (crypto_secretbox_open_easy(plain, cipher, clen, nonce, clients[idx].rx_key) != 0) {
                    fprintf(stderr, "Decrypt failed from client %d (fd %d)\n", idx, fd);
                
                } else {
                    size_t plen2 = clen - MAC_LEN;
                    plain[plen2] = 0;
                    printf("\n[From client %d on fd %d] %s\n", idx, fd, (char*)plain);

                    // --- LOGIKA LOGOWANIA ---
                    if (!clients[idx].logged_in) {
                        if (strncmp((char*)plain, "LOGIN ", 6) == 0) {
                            char login[64], pass[64];
                            if (sscanf((char*)plain + 6, "%63s %63s", login, pass) == 2) {
                                if (check_credentials(login, pass)) {
                                    clients[idx].logged_in = 1;
                                    strncpy(clients[idx].username, login, sizeof(clients[idx].username)-1);
                                    server_send_to_client(server_pk, idx, (unsigned char*)"LOGIN OK", 8);
                                    printf("Client %d (fd %d) logged in as %s\n", idx, fd, login);
                                } else {
                                    server_send_to_client(server_pk, idx, (unsigned char*)"LOGIN FAIL", 10);
                                    printf("Client %d (fd %d) failed login\n", idx, fd);
                                }
                            } else {
                                server_send_to_client(server_pk, idx, (unsigned char*)"BAD FORMAT", 10);
                            }
                        } else {
                            server_send_to_client(server_pk, idx, (unsigned char*)"LOGIN REQUIRED", 14);
                            printf("Client %d (fd %d) tried to send before login\n", idx, fd);
                        }
                    
                    } else {
                        // --- PRZEKAZANIE DO LOGIKI APLIKACJI ---
                        handle_client_message(server_pk, idx, plain, strlen((char*)plain));
                    }
                } // koniec udanego deszyfrowania
                printf("loracrypt-server> "); fflush(stdout);
            } // koniec 'else' (znaleziono klienta)
        } // koniec 'else' (pakiet danych)

        // --- KROK 5: Usuń przetworzony pakiet z bufora ---
        // (Jeśli doszło do błędu desynchronizacji, 'return' wyżej zapobiegł temu)
        memmove(buffer, buffer + total_packet_len, *buffer_len - total_packet_len);
        *buffer_len -= total_packet_len;
        
        // Pętla 'while(1)' spróbuje teraz przetworzyć kolejny pakiet,
        // który mógł być "sklejony" z poprzednim w buforze.
        
    } // koniec while(1)
}


// --- CAŁKOWICIE PRZEPISANA PĘTLA SERWERA ---

// Struktura do zarządzania połączeniami TCP i ich buforami
struct tcp_conn {
    int fd;
    unsigned char buffer[MAX_CONN_BUFFER];
    size_t buffer_len;
};


void interactive_loop_server(int ser_fd, int listen_fd, unsigned char server_pk[PK_LEN], unsigned char server_sk[SK_LEN]) {
    fd_set rd;
    char line[512];
    
    // Tablica na aktywne połączenia TCP
    struct tcp_conn tcp_connections[MAX_CLIENTS];
    int tcp_conn_count = 0;
    
    // Bufor dla portu szeregowego
    unsigned char lora_buffer[MAX_CONN_BUFFER];
    size_t lora_buffer_len = 0;
    
    // Zerowanie FD we wszystkich klientach (na start)
    for(int i=0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
    }

    printf("Server interactive. Commands:\n");
    printf("  /list\n");
    printf("  /sendall <text>\n");
    printf("  /send <idx> <text>\n");
    printf("Type text (default sends to client 0)\n");
    printf("loracrypt-server> "); fflush(stdout);

    while (1) {
        FD_ZERO(&rd);
        FD_SET(STDIN_FILENO, &rd);
        int max_fd = STDIN_FILENO;
        
        // 1. Dodaj port szeregowy (jeśli aktywny)
        if (ser_fd != -1) {
            FD_SET(ser_fd, &rd);
            if (ser_fd > max_fd) max_fd = ser_fd;
        }
        // 2. Dodaj gniazdo nasłuchujące (jeśli aktywne)
        if (listen_fd != -1) {
            FD_SET(listen_fd, &rd);
            if (listen_fd > max_fd) max_fd = listen_fd;
        }
        // 3. Dodaj wszystkich połączonych klientów TCP
        for (int i = 0; i < tcp_conn_count; i++) {
            FD_SET(tcp_connections[i].fd, &rd);
            if (tcp_connections[i].fd > max_fd) max_fd = tcp_connections[i].fd;
        }

        if (select(max_fd + 1, &rd, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select"); 
            exit(1); 
        }

        // --- OBSŁUGA STDIN (KONSOLA SERWERA) ---
        if (FD_ISSET(STDIN_FILENO, &rd)) {
            // (Ta sekcja jest bez zmian)
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t plen = strlen(line);
            if (plen && line[plen-1]=='\n') line[--plen]=0;
            if (plen == 0) { printf("loracrypt-server> "); fflush(stdout); continue; }

            if (strncmp(line, "/list", 5) == 0) {
                printf("Clients (%d):\n", client_count);
                for (int i=0;i<client_count;i++) {
                    printf(" %d: %s (fd=%d, type=%s, logged_in=%d) pk=", 
                           i, clients[i].username, clients[i].fd,
                           clients[i].type == CLIENT_LORA ? "LORA" : "TCP",
                           clients[i].logged_in);
                    for (int j=0;j<PK_LEN;j++) printf("%02x", clients[i].pk[j]);
                    printf("\n");
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            
            if (strncmp(line, "/sendall ", 9) == 0) {
                const char *msg = line + 9;
                send_to_all(server_pk, -1, (const unsigned char*)msg, strlen(msg));
                printf("Sent to all (%d clients)\n", client_count);
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            if (strncmp(line, "/send ", 6) == 0) {
                int idx = -1;
                int consumed = 0;
                if (sscanf(line+6, "%d%n", &idx, &consumed) >= 1) {
                    const char *msg = line + 6 + consumed;
                    while (*msg == ' ') msg++;
                    if (idx >= 0 && idx < client_count && *msg) {
                        char formatted_msg[MSG_BUF];
                        snprintf(formatted_msg, sizeof(formatted_msg), "\n[Server] %s", msg);
                        if (server_xsend_to_client(server_pk, idx, (const unsigned char*)formatted_msg, strlen(formatted_msg)) == 0) {
                            printf("Sent to client %d\n", idx);
                        } else {
                            fprintf(stderr, "Failed to send to client %d\n", idx);
                        }
                    } else {
                        printf("Invalid index or no message\n");
                    }
                } else {
                    printf("Usage: /send <idx> <text>\n");
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }

            // default: send to client 0
            if (client_count > 0) {
                char formatted_msg[MSG_BUF];
                snprintf(formatted_msg, sizeof(formatted_msg), "\n[Server] %s", line);
                if (server_xsend_to_client(server_pk, 0, (const unsigned char*)formatted_msg, strlen(formatted_msg)) == 0) {
                    printf("Sent to client 0\n");
                } else {
                    fprintf(stderr, "Failed to send to client 0\n");
                }
            } else {
                printf("No clients connected\n");
            }
            printf("loracrypt-server> "); fflush(stdout);
        } // --- KONIEC OBSŁUGI STDIN ---


        // --- OBSŁUGA NOWEGO POŁĄCZENIA TCP ---
        if (listen_fd != -1 && FD_ISSET(listen_fd, &rd)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int new_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
            
            if (new_fd < 0) {
                perror("accept");
            } else if (tcp_conn_count >= MAX_CLIENTS) {
                fprintf(stderr, "Max TCP clients reached, rejecting fd %d\n", new_fd);
                close(new_fd); // Odrzuć połączenie
            } else {
                printf("New TCP connection from %s:%d on fd %d\n",
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), new_fd);
                
                // Ustaw gniazdo jako nieblokujące
                fcntl(new_fd, F_SETFL, O_NONBLOCK); 
                
                // Dodaj do naszej tablicy połączeń
                tcp_connections[tcp_conn_count].fd = new_fd;
                tcp_connections[tcp_conn_count].buffer_len = 0;
                tcp_conn_count++;
            }
        } // --- KONIEC OBSŁUGI NOWEGO POŁĄCZENIA ---


        // --- OBSŁUGA DANYCH Z PORTU SZEREGOWEGO ---
        if (ser_fd != -1 && FD_ISSET(ser_fd, &rd)) {
            unsigned char temp_buf[1024];
            // Czytaj NIEBLOKUJĄCO
            ssize_t r = read(ser_fd, temp_buf, sizeof(temp_buf));
            
            if (r > 0) {
                // Mamy dane. Dodaj do bufora LoRa.
                if (lora_buffer_len + r > MAX_CONN_BUFFER) {
                    fprintf(stderr, "LoRa buffer overflow, discarding data\n");
                    lora_buffer_len = 0; // Zresetuj bufor
                } else {
                    memcpy(lora_buffer + lora_buffer_len, temp_buf, r);
                    lora_buffer_len += r;
                    // Próbuj przetworzyć pakiety z bufora
                    process_data_buffer(lora_buffer, &lora_buffer_len, ser_fd, CLIENT_LORA, server_pk, server_sk);
                }
            } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read(ser_fd)");
                // (Nie robimy nic, port szeregowy zostaje otwarty)
            }
        } // --- KONIEC OBSŁUGI SERIALA ---


        // --- OBSŁUGA DANYCH OD KLIENTÓW TCP ---
        for (int i = 0; i < tcp_conn_count; i++) {
            struct tcp_conn *conn = &tcp_connections[i];
            
            if (FD_ISSET(conn->fd, &rd)) {
                unsigned char temp_buf[1024];
                // Czytaj NIEBLOKUJĄCO
                ssize_t r = read(conn->fd, temp_buf, sizeof(temp_buf));
                
                if (r > 0) {
                    // Mamy dane. Dodaj do bufora tego klienta.
                    if (conn->buffer_len + r > MAX_CONN_BUFFER) {
                        fprintf(stderr, "TCP client fd %d buffer overflow, disconnecting\n", conn->fd);
                        r = 0; // Traktuj jak rozłączenie
                    } else {
                        memcpy(conn->buffer + conn->buffer_len, temp_buf, r);
                        conn->buffer_len += r;
                        // Próbuj przetworzyć pakiety z bufora
                        process_data_buffer(conn->buffer, &conn->buffer_len, conn->fd, CLIENT_TCP, server_pk, server_sk);
                    }
                }
                
                if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    // r == 0 -> EOF (Klient się rozłączył)
                    // r < 0 -> Błąd odczytu
                    if (r == 0) {
                        printf("TCP client on fd %d disconnected (EOF)\n", conn->fd);
                    } else {
                        perror("read(tcp_fd)");
                    }
                    
                    close(conn->fd);
                    
                    // Znajdź klienta (jeśli był zahandshake'owany) i oznacz jako nieaktywny
                    for (int k = 0; k < client_count; k++) {
                        if (clients[k].fd == conn->fd) {
                            printf("Client %d (%s) marked as disconnected.\n", k, clients[k].username);
                            clients[k].fd = -1; // Oznacz jako nieaktywny
                            clients[k].logged_in = 0; // Wyloguj
                            break;
                        }
                    }
                    
                    // Usuń połączenie z tablicy (przez nadpisanie ostatnim)
                    tcp_connections[i] = tcp_connections[tcp_conn_count - 1];
                    tcp_conn_count--;
                    i--; // Popraw licznik pętli
                }
            }
        } // --- KONIEC OBSŁUGI KLIENTÓW TCP ---
    } // --- KONIEC pętli while(1) ---
} // --- KONIEC interactive_loop_server ---


// ------------------------------------------------------------------
// --- NOWA LOGIKA KLIENTA (Z POPRAWKAMI) ---
// ------------------------------------------------------------------

/**
 * @brief Przetwarza bufor wejściowy klienta, szuka pakietów,
 * odszyfrowuje je i drukuje w oknie ncurses.
 */
void process_client_buffer(unsigned char *buffer, size_t *buffer_len, 
                           unsigned char rx_key[SESSION_KEY_LEN],
                           WINDOW *msg_win, WINDOW *input_win, char *input_buf)
{
    // Pętla przetwarzająca wszystkie kompletne pakiety w buforze
    while (1) {
        // Krok 1: Sprawdź nagłówek
        if (*buffer_len < 2) {
            return; // Za mało danych, czekaj
        }
        
        uint16_t flen = ((uint16_t)buffer[0] << 8) | buffer[1];
        
        // Krok 2: Sprawdź, czy pakiet to nie śmieć (np. zły handshake)
        if (flen == HANDSHAKE_HDR) {
             //fprintf(stderr, "Unexpected handshake received, discarding\n");
             // Usuń śmieci z bufora
             size_t handshake_len = 2 + HELLO_LEN + PK_LEN;
             if (*buffer_len >= handshake_len) {
                memmove(buffer, buffer + handshake_len, *buffer_len - handshake_len);
                *buffer_len -= handshake_len;
             } else {
                 *buffer_len = 0; // Niekompletny, zresetuj
             }
             continue; // Spróbuj kolejny pakiet
        }

        // Sprawdź poprawność długości (jak w starym kodzie)
        if (flen == 0 || flen < PK_LEN + NONCE_LEN + MAC_LEN || flen > MAX_FRAME) {
            //fprintf(stderr, "Invalid frame length %u, discarding buffer\n", flen);
            *buffer_len = 0; // Zła długość, resetuj bufor
            return;
        }

        size_t total_packet_len = 2 + flen;

        // Krok 3: Sprawdź, czy mamy cały pakiet
        if (*buffer_len < total_packet_len) {
            return; // Niekompletny, czekaj na resztę
        }

        // Krok 4: Mamy cały pakiet. Przetwórz go.
        // unsigned char *sender_pk = buffer + 2; // (PK serwera, ale ignorujemy)
        unsigned char *enc_buf = buffer + 2 + PK_LEN;
        size_t enc_len = flen - PK_LEN;

        unsigned char *nonce = enc_buf;
        unsigned char *cipher = enc_buf + NONCE_LEN;
        size_t clen = enc_len - NONCE_LEN;
        unsigned char plain[MAX_PLAINTEXT+1];

        // Spróbuj odszyfrować
        if (crypto_secretbox_open_easy(plain, cipher, clen, nonce, rx_key) == 0) {
            // SUKCES! To pakiet dla nas.
            plain[clen - MAC_LEN] = 0;
            
            // Logika PING/PONG (zmienne globalne)
            extern int waiting_for_pong;
            extern struct timeval ping_start;

            if (waiting_for_pong && strcasecmp((char*)plain, "pong") == 0) {
                struct timeval ping_end;
                gettimeofday(&ping_end, NULL);
                long ms = (ping_end.tv_sec - ping_start.tv_sec) * 1000L +
                        (ping_end.tv_usec - ping_start.tv_usec) / 1000L;
                wprintw(msg_win, "Server responded \"%s\" RTT=%ld ms", plain, ms);
                wrefresh(msg_win);
                waiting_for_pong = 0;
            } else {
                // Zwykła wiadomość
                wprintw(msg_win, "%s", plain);
                wrefresh(msg_win);
            }

            // Odśwież input
            werase(input_win);
            mvwprintw(input_win, 0, 0, "loracrypt-client> %s", input_buf);
            wrefresh(input_win);
        } else {
            // BŁĄD DESZYFROWANIA. 
            // To był pakiet dla kogoś innego. Zignoruj go.
            // (Można tu dodać logowanie błędu)
            // fprintf(stderr, "Decrypt failed, ignoring packet\n");
        }
        
        // Krok 5: Usuń przetworzony (lub zignorowany) pakiet z bufora
        memmove(buffer, buffer + total_packet_len, *buffer_len - total_packet_len);
        *buffer_len -= total_packet_len;
        
        // Pętla while(1) spróbuje teraz znaleźć kolejny pakiet w buforze

    } // koniec while(1)
}


int logged_in = 0;
void interactive_loop_client(int ser,
unsigned char my_pk[PK_LEN], unsigned char my_sk[SK_LEN],
unsigned char server_pk[PK_LEN],
unsigned char rx_key[SESSION_KEY_LEN], unsigned char tx_key[SESSION_KEY_LEN])
{
    // --- Sekcja logowania (używa blokującego read_all) ---
    if(!logged_in){
        char login[64], password[64], credentials[128];
        unsigned char nonce[NONCE_LEN];
        unsigned char ctext[NONCE_LEN + 128 + MAC_LEN];

        while (!logged_in) {
            printf("Login: ");
            fflush(stdout);
            if (!fgets(login, sizeof(login), stdin)) exit(1);
            login[strcspn(login, "\n")] = 0;

            printf("Password: ");
            fflush(stdout);
            if (!fgets(password, sizeof(password), stdin)) exit(1);
            password[strcspn(password, "\n")] = 0;

            snprintf(credentials, sizeof(credentials), "LOGIN %s %s", login, password);

            randombytes_buf(nonce, NONCE_LEN);
            memcpy(ctext, nonce, NONCE_LEN);
            crypto_secretbox_easy(ctext + NONCE_LEN, (unsigned char*)credentials,
                                  strlen(credentials), nonce, tx_key);

            uint16_t flen = PK_LEN + NONCE_LEN + strlen(credentials) + MAC_LEN;
            unsigned char hdr[2] = { (uint8_t)(flen >> 8), (uint8_t)flen };

            // *** DODAJ TĘ LINIĘ TUTAJ ***
            // Wyczyść bufor wejściowy (Input) ze wszystkich "śmieci" LoRa
            // zanim wyślemy żądanie i zaczniemy czekać na odpowiedź.
            tcflush(ser, TCIFLUSH); 
            // ***************************

            if (write_all(ser, hdr, 2) != 2 ||
                write_all(ser, my_pk, PK_LEN) != PK_LEN ||
                write_all(ser, ctext, flen - PK_LEN) != flen - PK_LEN) {
                fprintf(stderr, "Write failed during login\n");
                exit(1);
            }

            // odbiór odpowiedzi (blokujący)
            unsigned char hdr_in[2];
            if (read_all(ser, hdr_in, 2) != 2) { fprintf(stderr, "Read failed during login\n"); exit(1); }
            uint16_t flen_in = ((uint16_t)hdr_in[0]<<8) | hdr_in[1];
            
            if (flen_in < PK_LEN + NONCE_LEN + MAC_LEN || flen_in > MAX_FRAME) {
                fprintf(stderr, "Invalid frame length during login: %u\n", flen_in);
                continue;
            }

            unsigned char sender_pk_in[PK_LEN];
            if (read_all(ser, sender_pk_in, PK_LEN) != PK_LEN) { fprintf(stderr, "Short read sender pk\n"); exit(1); }
            
            unsigned char encbuf[MAX_FRAME];
            size_t enc_len = flen_in - PK_LEN;
            if (read_all(ser, encbuf, enc_len) != (ssize_t)enc_len) { fprintf(stderr, "Short read login response\n"); exit(1); }

            unsigned char *nonce_in = encbuf;
            unsigned char *cipher_in = encbuf + NONCE_LEN;
            size_t clen_in = enc_len - NONCE_LEN;
            unsigned char plain[MAX_PLAINTEXT + 1];
            if (crypto_secretbox_open_easy(plain, cipher_in, clen_in, nonce_in, rx_key) != 0) { fprintf(stderr, "Login decrypt failed\n"); continue; }

            plain[clen_in - MAC_LEN] = 0;
            if (strcmp((char*)plain, "LOGIN OK") == 0) {
                printf("✅ Zalogowano pomyślnie!\n");
                logged_in = 1;
            } else {
                printf("❌ Logowanie nieudane: %s\n", plain);
            }
        }
    }
    
    // --- Inicjalizacja Ncurses ---
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    WINDOW *msg_win = newwin(LINES-1, COLS, 0, 0);
    WINDOW *input_win = newwin(1, COLS, LINES-1, 0);
    keypad(input_win, TRUE);
    scrollok(msg_win, TRUE);

    char input_buf[MAX_IN] = {0};
    int in_len = 0;
    int first_print = 1;
    char *history[MAX_HISTORY] = {0};
    int history_count = 0;
    int history_pos = -1;

    mvwprintw(input_win, 0, 0, "loracrypt-client> ");
    wrefresh(input_win);
    wrefresh(msg_win);
    
    // --- NOWY BUFOR DLA PĘTLI GŁÓWNEJ ---
    unsigned char input_buffer[MAX_CONN_BUFFER];
    size_t input_buffer_len = 0;
    
    // --- ZMODYFIKOWANA GŁÓWNA PĘTLA (NIEBLOKUJĄCA) ---
    while (1) {
    
    // --- 1) obsługa klawiatury ---
    wtimeout(input_win, 100); // Czekaj 100ms na klawisz
    int ch = wgetch(input_win);
    if (ch != ERR) {
        if (ch == KEY_UP) {
            if (history_count > 0) {
                if (history_pos < 0) history_pos = history_count - 1;
                else if (history_pos > 0) history_pos--;
                strncpy(input_buf, history[history_pos], MAX_IN - 1);
                in_len = strlen(input_buf);
            }
        }
        else if (ch == KEY_DOWN) {
            if (history_count > 0 && history_pos >= 0) {
                history_pos++;
                if (history_pos >= history_count) {
                    history_pos = -1;
                    in_len = 0;
                    input_buf[0] = 0;
                } else {
                    strncpy(input_buf, history[history_pos], MAX_IN - 1);
                    in_len = strlen(input_buf);
                }
            }
        }
        else if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
            if (in_len > 0) {
                in_len--;
                input_buf[in_len] = 0;
            }
            history_pos = -1;
        }
        else if (ch == '\n' || ch == '\r') {
            if (in_len > 0) {
                if (history_count < MAX_HISTORY) {
                    history[history_count++] = strdup(input_buf);
                } else {
                    free(history[0]);
                    memmove(history, history+1, sizeof(char*) * (MAX_HISTORY-1));
                    history[MAX_HISTORY-1] = strdup(input_buf);
                }
                history_pos = -1;

                char* trimmed = trim(input_buf);
                if (strncasecmp(trimmed, "ping", 4)==0 || strncasecmp(trimmed, "/ping",5)==0) {
                    gettimeofday(&ping_start, NULL);
                    waiting_for_pong = 1;
                }

                unsigned char nonce[NONCE_LEN];
                randombytes_buf(nonce, NONCE_LEN);
                unsigned char ctext[NONCE_LEN + MAX_PLAINTEXT + MAC_LEN];
                memcpy(ctext, nonce, NONCE_LEN);
                crypto_secretbox_easy(ctext + NONCE_LEN,
                                      (unsigned char*)input_buf,
                                      in_len,
                                      nonce,
                                      tx_key);
                uint16_t flen = PK_LEN + NONCE_LEN + in_len + MAC_LEN;
                unsigned char hdr[2] = { (uint8_t)(flen>>8), (uint8_t)flen };

                // Wysyłanie jest blokujące (write_all), co jest OK
                write_all(ser, hdr, 2);
                write_all(ser, my_pk, PK_LEN);
                write_all(ser, ctext, flen - PK_LEN);

                if (first_print) {
                    wprintw(msg_win, "\n[You] %s\n", input_buf);
                    first_print = 0;
                } else {
                    wprintw(msg_win, "\n\n[You] %s\n", input_buf);
                }
                wrefresh(msg_win);
            }
            in_len = 0;
            input_buf[0] = 0;
        }
        else if (isprint(ch) && in_len < MAX_IN-1) {
            input_buf[in_len++] = (char)ch;
            input_buf[in_len] = 0;
            history_pos = -1;
        }
        // Odśwież widok wpisywania
        werase(input_win);
        mvwprintw(input_win, 0, 0, "loracrypt-client> %s", input_buf);
        wrefresh(input_win);
    } // --- koniec obsługi klawiatury ---


    // --- 2) obsługa przychodzącej ramki z serwera (NIEBLOKUJĄCA) ---
    fd_set rd;
    struct timeval tv = { 0, 0 }; // Zerowy timeout = nie czekaj
    FD_ZERO(&rd);
    FD_SET(ser, &rd);
    
    int sel_ret = select(ser+1, &rd, NULL, NULL, &tv);
    
    if (sel_ret > 0 && FD_ISSET(ser, &rd)) {
        // Są dane! Czytaj je w sposób nieblokujący
        //unsigned char temp_buf[1024];
        //ssize_t r = read(ser, temp_buf, sizeof(temp_buf));
        size_t space_left = MAX_CONN_BUFFER - input_buffer_len;
        if (space_left == 0) {
            // Bufor jest pełny, a process_client_buffer go nie opróżnił
            // (może czeka na resztę pakietu, który jest > MAX_CONN_BUFFER)
            fprintf(stderr, "Client input buffer full, logic error or packet too large\n");
            input_buffer_len = 0; // Zresetuj, aby uniknąć pętli
            space_left = MAX_CONN_BUFFER;
        }
    
        ssize_t r = read(ser, input_buffer + input_buffer_len, space_left);
        
        if (r > 0) {
            // Mamy dane, dodaj je do bufora
            /*if (input_buffer_len + r > MAX_CONN_BUFFER) {
                 fprintf(stderr, "Client input buffer overflow, discarding\n");
                 input_buffer_len = 0;
            } else {
                memcpy(input_buffer + input_buffer_len, temp_buf, r);
                input_buffer_len += r;*/
                input_buffer_len += r;
                
                // Próbuj przetworzyć bufor
                process_client_buffer(input_buffer, &input_buffer_len, rx_key, 
                                      msg_win, input_win, input_buf);
            //}
        } else if (r == 0) {
            // EOF - serwer się rozłączył
            wprintw(msg_win, "\n*** SERVER DISCONNECTED ***\n");
            wrefresh(msg_win);
            sleep(2);
            break; // Zakończ pętlę klienta
        } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Prawdziwy błąd odczytu
            perror("read(client)");
            sleep(2);
            break; // Zakończ pętlę klienta
        }
        
    } else if (sel_ret < 0) {
        perror("select(client)");
        break; // Błąd select, zakończ
    }

} // --- Koniec głównej pętli while(1) ---

// --- Sprzątanie Ncurses ---
for (int i = 0; i < history_count; i++)
    free(history[i]);
delwin(msg_win);
delwin(input_win);
endwin();
}


// --- FUNKCJA main ---
int main(int argc, char *argv[]) {
    if ((argc != 3 && argc != 4) || (argv[1][1] != 's' && argv[1][1] != 'c')) {
        fprintf(stderr,
            "Usage: %s -s|-c <device_or_IP:PORT>\n"
            " -s server mode, -c client mode\n"
            " Example (Serial): %s -s /dev/tty.usbserial <baudrate>\n"
            " Example (Network):  %s -c 127.0.0.1:5000\n", 
            argv[0], argv[0], argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    
    char *dev_or_addr = argv[2];
    int is_server = (argv[1][1] == 's');
    
    char ip_buf[256];
    int port = 0;
    
    int main_fd = -1; // Dla klienta lub serwera serial
    int listen_fd = -1; // Dla serwera TCP

    if (argc == 4) {
        // Czwarty argument jest dozwolony tylko w trybie serwera (-s)
        // (zgodnie z Twoim komunikatem Usage)
        printf("Baudrate usera: %s", argv[3]);
            char *endptr; // Do sprawdzania błędów konwersji
            
            // Konwertuj tekst z argv[3] na liczbę (long)
            BAUDRATE = strtol(argv[3], &endptr, 10);
            
            // Sprawdź, czy konwersja się udała i czy podano poprawną liczbę
            if (*endptr != '\0' || BAUDRATE <= 0) {
                fprintf(stderr, "Błędna lub niepoprawna wartość baudrate: %s\n", argv[3]);
                return 1;
            }
    }
    
    // Sprawdź czy to adres sieciowy
    if (is_network_address(dev_or_addr, ip_buf, sizeof(ip_buf), &port)) {
        if (is_server) {
            // Serwer: otwórz gniazdo nasłuchujące
            listen_fd = open_server_socket(ip_buf, port);
            main_fd = -1; // Serwer TCP nie ma jednego "głównego" fd, tylko 'listen_fd'
        } else {
            // Klient: połącz się
            main_fd = open_client_socket(ip_buf, port);
        }
    } else {
        // To port szeregowy
        main_fd = open_serial(dev_or_addr);
        if (is_server) {
            listen_fd = -1; // Serwer serial nie nasłuchuje na TCP
        }
    }

    unsigned char my_pk[PK_LEN], my_sk[SK_LEN], peer_pk[PK_LEN];
    unsigned char rx_key[SESSION_KEY_LEN], tx_key[SESSION_KEY_LEN];

    if (is_server) {
        printf("*** RUNNING AS SERVER ***\n");
        if (crypto_kx_keypair(my_pk, my_sk) != 0) {
            fprintf(stderr, "crypto_kx_keypair failed (server)\n"); return 1;
        }
        printf("Server PK: ");
        for (int i=0;i<PK_LEN;i++) printf("%02x", my_pk[i]);
        printf("\n");
        
        // Wywołaj NOWĄ, nieblokującą pętlę serwera
        interactive_loop_server(main_fd, listen_fd, my_pk, my_sk);
        
    } else {
        printf("*** RUNNING AS CLIENT ***\n");
        // Pętla klienta (handshake jest blokujący, reszta nie)
        handshake_client(main_fd, my_pk, my_sk, peer_pk, rx_key, tx_key);
        printf("Gotowy do komunikacji zaszyfrowanej!\n");
        // Wywołaj NOWĄ, nieblokującą pętlę klienta
        interactive_loop_client(main_fd, my_pk, my_sk, peer_pk, rx_key, tx_key);
    }

    if (main_fd != -1) close(main_fd);
    if (listen_fd != -1) close(listen_fd);
    
    return 0;
}