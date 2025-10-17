// loracrypt_multi.c
// Multi-client LoRa+UART with libsodium
// gcc loracrypt_multi.c -o loracrypt -lsodium

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

#define NONCE_LEN crypto_secretbox_NONCEBYTES // 24
#define MAC_LEN crypto_secretbox_MACBYTES // 16
#define KEY_LEN crypto_secretbox_KEYBYTES // 32
//#define PK_LEN crypto_kx_PUBLICKEYBYTES // 32
#define SK_LEN crypto_kx_SECRETKEYBYTES // 32
//#define SESSION_KEY_LEN crypto_kx_SESSIONKEYBYTES // 32

#define MAX_FRAME 240
//#define MAX_PLAINTEXT (MAX_FRAME - NONCE_LEN - MAC_LEN - PK_LEN)
#define HELLO_MSG "HELLO test123"
#define HELLO_LEN (sizeof(HELLO_MSG)-1)
#define HANDSHAKE_HDR 0xFFFF
#define MAX_CLIENTS 32

// for ncurses
#define MAX_IN 512 // bufor wejściowy
#define MSG_BUF 1024 // maks. długość wiadomości przychodzącej

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
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tcsetattr(fd, TCSANOW, &tio);
    return fd;
}

// Dokładnie czyta len bajtów
ssize_t read_all(int fd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, (unsigned char*)buf + total, len - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            }
            return -1;
        }
        if (r == 0) {
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

struct client_t clients[MAX_CLIENTS];
int client_count = 0;

// Dodaj klienta (jeśli nie ma) i zwróć indeks lub -1
int add_client(const unsigned char client_pk[PK_LEN],
               const unsigned char server_pk[PK_LEN], const unsigned char server_sk[SK_LEN]) {
    // sprawdź czy już istnieje
    for (int i = 0; i < client_count; ++i) {
        if (memcmp(clients[i].pk, client_pk, PK_LEN) == 0) return i;
    }
    if (client_count >= MAX_CLIENTS) return -1;
    memcpy(clients[client_count].pk, client_pk, PK_LEN);
    // wylicz sesyjne klucze (server role)
    if (crypto_kx_server_session_keys(clients[client_count].rx_key, clients[client_count].tx_key,
            server_pk, server_sk, client_pk) != 0) {
        fprintf(stderr, "crypto_kx_server_session_keys failed for new client\n");
        return -1;
    }
    int idx = client_count++;
    printf("New client added idx=%d pk=", idx);
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

// Funkcja do wysłania zaszyfrowanej wiadomości od serwera do jednego klienta.
// (server_pk - 32 bajty, serfd - fd, client_idx, plaintext+len)
int server_send_to_client(int serfd, const unsigned char server_pk[PK_LEN], int client_idx,
                          const unsigned char *plain, size_t plen) {
    if (client_idx < 0 || client_idx >= client_count) return -1;
    if (plen > MAX_PLAINTEXT) return -1;

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);

    unsigned char ctext[NONCE_LEN + MAX_PLAINTEXT + MAC_LEN];
    memcpy(ctext, nonce, NONCE_LEN);
    crypto_secretbox_easy(ctext + NONCE_LEN, plain, plen, nonce, clients[client_idx].tx_key);

    uint16_t flen = PK_LEN + NONCE_LEN + plen + MAC_LEN;
    unsigned char hdr[2] = { (uint8_t)(flen>>8), (uint8_t)flen };

    if (write_all(serfd, hdr, 2) != 2) return -1;
    if (write_all(serfd, server_pk, PK_LEN) != PK_LEN) return -1;
    if (write_all(serfd, ctext, flen - PK_LEN) != flen - PK_LEN) return -1;
    return 0;
}

// HANDSHAKE (klient) - zmienione: używa HANDSHAKE_HDR
void handshake_client(int ser,
    unsigned char my_pk[PK_LEN], unsigned char my_sk[SK_LEN],
    unsigned char server_pk[PK_LEN],
    unsigned char rx_key[SESSION_KEY_LEN], unsigned char tx_key[SESSION_KEY_LEN]) {

    if (crypto_kx_keypair(my_pk, my_sk) != 0) {
        fprintf(stderr, "crypto_kx_keypair failed\n"); exit(1);
    }

    // Wyślij HANDSHAKE_HDR
    uint16_t hh = HANDSHAKE_HDR;
    unsigned char hh_buf[2] = { (uint8_t)(hh>>8), (uint8_t)hh };
    if (write_all(ser, hh_buf, 2) != 2) { fprintf(stderr, "Sending handshake hdr failed\n"); exit(1); }

    // Wyślij HELLO
    if (write_all(ser, HELLO_MSG, HELLO_LEN) != HELLO_LEN) { fprintf(stderr, "Sending HELLO failed\n"); exit(1); }

    // Wyślij PK klienta
    if (write_all(ser, my_pk, PK_LEN) != PK_LEN) { fprintf(stderr, "Sending client PK failed\n"); exit(1); }
    printf("Wysłano handshake (HELLO + client PK) do serwera\n");

    // Odbierz PK serwera
    if (read_all(ser, server_pk, PK_LEN) != PK_LEN) { fprintf(stderr, "Reading server PK failed\n"); exit(1); }
    printf("Odebrano PK serwera\n");

    if (crypto_kx_client_session_keys(rx_key, tx_key, my_pk, my_sk, server_pk) != 0) {
        fprintf(stderr, "crypto_kx_client_session_keys failed\n"); exit(1);
    }
    printf("Session keys computed (client)\n");
}

// Handshake handler na serwerze: wywoływane gdy wykryjemy HANDSHAKE_HDR
// Odczytuje HELLO i client_pk, wysyła server_pk i dodaje klienta.
int handle_handshake_on_server(int ser, const unsigned char server_pk[PK_LEN], const unsigned char server_sk[SK_LEN]) {
    // po odczytaniu nagłówka (0xFFFF) oczekujemy HELLO + client_pk
    unsigned char hello[HELLO_LEN+1];
    if (read_all(ser, hello, HELLO_LEN) != HELLO_LEN) {
        fprintf(stderr, "Short read HELLO during handshake\n");
        return -1;
    }
    hello[HELLO_LEN]=0;
    if (strncmp((char*)hello, HELLO_MSG, HELLO_LEN) != 0) {
        fprintf(stderr, "Bad HELLO content during handshake: %s\n", hello);
        // nadal spróbuj odczytać client pk to utrzymaja stan
    }
    unsigned char client_pk[PK_LEN];
    if (read_all(ser, client_pk, PK_LEN) != PK_LEN) {
        fprintf(stderr, "Reading client PK failed in handshake\n");
        return -1;
    }
    // Wyślij server_pk do klienta
    if (write_all(ser, server_pk, PK_LEN) != PK_LEN) {
        fprintf(stderr, "Sending server PK failed in handshake\n");
        return -1;
    }
    // Dodaj klienta (wyliczenie kluczy sesyjnych)
    int idx = add_client(client_pk, server_pk, (unsigned char*)server_sk);
    if (idx < 0) {
        fprintf(stderr, "Failed to add client (limit?)\n");
        return -1;
    }
    printf("Handshake complete, client idx=%d\n", idx);
    return idx;
}

// Funkcja interaktywna (działa inaczej dla serwera i klienta)
void interactive_loop_server(int ser, unsigned char server_pk[PK_LEN], unsigned char server_sk[SK_LEN]) {
    fd_set rd;
    char line[512];
    unsigned char buf[MAX_FRAME];
    printf("Server interactive. Commands:\n");
    printf("  /list\n");
    printf("  /sendall <text>\n");
    printf("  /send <idx> <text>\n");
    printf("Type text (default sends to client 0)\n");
    printf("loracrypt-server> "); fflush(stdout);

    while (1) {
        FD_ZERO(&rd);
        FD_SET(STDIN_FILENO, &rd);
        FD_SET(ser, &rd);
        int maxfd = (ser > STDIN_FILENO ? ser : STDIN_FILENO) + 1;
        if (select(maxfd, &rd, NULL, NULL, NULL) < 0) { perror("select"); exit(1); }

        // stdin
        if (FD_ISSET(STDIN_FILENO, &rd)) {
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t plen = strlen(line);
            if (plen && line[plen-1]=='\n') line[--plen]=0;
            if (plen == 0) { printf("loracrypt-server> "); fflush(stdout); continue; }

            if (strncmp(line, "/list", 5) == 0) {
                printf("Clients (%d):\n", client_count);
                for (int i=0;i<client_count;i++) {
                    printf(" %d: ", i);
                    for (int j=0;j<PK_LEN;j++) printf("%02x", clients[i].pk[j]);
                    printf("\n");
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            if (strncmp(line, "/sendall ", 9) == 0) {
                const char *msg = line + 9;
                for (int i=0;i<client_count;i++) {
                    if (server_send_to_client(ser, server_pk, i, (const unsigned char*)msg, strlen(msg)) != 0) {
                        fprintf(stderr, "Failed to send to client %d\n", i);
                    }
                }
                printf("Sent to all (%d clients)\n", client_count);
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            if (strncmp(line, "/send ", 6) == 0) {
                // format: /send <idx> <text>
                int idx = -1;
                int consumed = 0;
                if (sscanf(line+6, "%d%n", &idx, &consumed) >= 1) {
                    const char *msg = line + 6 + consumed;
                    while (*msg == ' ') msg++;
                    if (idx >= 0 && idx < client_count && *msg) {
                        if (server_send_to_client(ser, server_pk, idx, (const unsigned char*)msg, strlen(msg)) == 0) {
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

            // default: send to client 0 if exists
            if (client_count > 0) {
                if (server_send_to_client(ser, server_pk, 0, (const unsigned char*)line, strlen(line)) == 0) {
                    printf("Sent to client 0\n");
                } else {
                    fprintf(stderr, "Failed to send to client 0\n");
                }
            } else {
                printf("No clients connected\n");
            }
            printf("loracrypt-server> "); fflush(stdout);
        }

        // serial
        if (FD_ISSET(ser, &rd)) {
            unsigned char hdr[2];
            if (read_all(ser, hdr, 2) != 2) {
                fprintf(stderr, "Serial closed or short hdr\n");
                break;
            }
            uint16_t flen = ((uint16_t)hdr[0]<<8) | hdr[1];
            if (flen == HANDSHAKE_HDR) {
                // handshake flow
                if (handle_handshake_on_server(ser, server_pk, server_sk) < 0) {
                    fprintf(stderr, "Handshake failed\n");
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            if (flen == 0 || flen > MAX_FRAME) {
                fprintf(stderr, "Frame too big (%u), discarding\n", flen);
                size_t togo = flen;
                unsigned char trash[128];
                while (togo) {
                    size_t chunk = togo > sizeof(trash) ? sizeof(trash) : togo;
                    if (read_all(ser, trash, chunk) != (ssize_t)chunk) break;
                    togo -= chunk;
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            // normal message: first PK_LEN bytes = sender pk
            if (flen < PK_LEN + NONCE_LEN + MAC_LEN) {
                fprintf(stderr, "Frame too small for sender pk + crypto\n");
                // read and drop flen
                unsigned char trash[256];
                size_t togo = flen;
                while (togo) {
                    size_t chunk = togo > sizeof(trash) ? sizeof(trash) : togo;
                    if (read_all(ser, trash, chunk) != (ssize_t)chunk) break;
                    togo -= chunk;
                }
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            unsigned char sender_pk[PK_LEN];
            if (read_all(ser, sender_pk, PK_LEN) != PK_LEN) {
                fprintf(stderr, "Short read sender pk\n"); break;
            }
            size_t enc_len = flen - PK_LEN;
            if (enc_len > sizeof(buf)) {
                fprintf(stderr, "enc_len too big\n"); break;
            }
            if (read_all(ser, buf, enc_len) != (ssize_t)enc_len) {
                fprintf(stderr, "Short read enc payload\n"); break;
            }
            int idx = find_client_by_pk(sender_pk);
            if (idx < 0) {
                fprintf(stderr, "Unknown sender pk, ignoring (or run handshake?)\n");
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            unsigned char *nonce = buf;
            unsigned char *cipher = buf + NONCE_LEN;
            size_t clen = enc_len - NONCE_LEN;
            unsigned char plain[MAX_PLAINTEXT+1];
            if (crypto_secretbox_open_easy(plain, cipher, clen, nonce, clients[idx].rx_key) != 0) {
                fprintf(stderr, "Decrypt failed from client %d\n", idx);
                printf("loracrypt-server> "); fflush(stdout);
                continue;
            }
            size_t plen2 = clen - MAC_LEN;
            plain[plen2] = 0;
printf("\n[From client %d] %s\n", idx, (char*)plain);

// jeśli klient jeszcze nie zalogowany
if (!clients[idx].logged_in) {
    if (strncmp((char*)plain, "LOGIN ", 6) == 0) {
        char login[64], pass[64];
        if (sscanf((char*)plain + 6, "%63s %63s", login, pass) == 2) {
            if (check_credentials(login, pass)) {
                clients[idx].logged_in = 1;
                strncpy(clients[idx].username, login, sizeof(clients[idx].username)-1);
                server_send_to_client(ser, server_pk, idx, (unsigned char*)"LOGIN OK", 8);
                printf("Client %d logged in as %s\n", idx, login);
            } else {
                server_send_to_client(ser, server_pk, idx, (unsigned char*)"LOGIN FAIL", 10);
                printf("Client %d failed login\n", idx);
            }
        } else {
            server_send_to_client(ser, server_pk, idx, (unsigned char*)"BAD FORMAT", 10);
        }
    } else {
        server_send_to_client(ser, server_pk, idx, (unsigned char*)"LOGIN REQUIRED", 14);
        printf("Client %d tried to send before login\n", idx);
    }
    printf("loracrypt-server> "); fflush(stdout);
    continue;
}

// tu dopiero normalna wiadomość jeśli logged_in==1
handle_client_message(ser, server_pk, idx, plain, strlen((char*)plain));
printf("loracrypt-server> "); fflush(stdout);
        }
    }
}

int logged_in = 0;

void interactive_loop_client(int ser,
unsigned char my_pk[PK_LEN], unsigned char my_sk[SK_LEN],
unsigned char server_pk[PK_LEN],
unsigned char rx_key[SESSION_KEY_LEN], unsigned char tx_key[SESSION_KEY_LEN])
{
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

            if (write_all(ser, hdr, 2) != 2 ||
                write_all(ser, my_pk, PK_LEN) != PK_LEN ||
                write_all(ser, ctext, flen - PK_LEN) != flen - PK_LEN) {
                fprintf(stderr, "Write failed during login\n");
                exit(1);
            }

            // odbiór odpowiedzi
            unsigned char hdr_in[2];
            if (read_all(ser, hdr_in, 2) != 2) { fprintf(stderr, "Serial closed during login\n"); exit(1); }
            uint16_t flen_in = ((uint16_t)hdr_in[0]<<8) | hdr_in[1];
            unsigned char sender_pk[PK_LEN];
            if (read_all(ser, sender_pk, PK_LEN) != PK_LEN) { fprintf(stderr, "Short read sender pk\n"); exit(1); }
            unsigned char encbuf[MAX_FRAME];
            if (read_all(ser, encbuf, flen_in - PK_LEN) != (ssize_t)(flen_in - PK_LEN)) { fprintf(stderr, "Short read login response\n"); exit(1); }

            unsigned char *nonce_in = encbuf;
            unsigned char *cipher_in = encbuf + NONCE_LEN;
            size_t clen_in = flen_in - PK_LEN - NONCE_LEN;
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
// --- inicjalizacja ncurses ---
initscr();
cbreak();
noecho();
keypad(stdscr, TRUE);
// okno z historią (scrollok pozwala na scrollowanie gdy jest pełne)
WINDOW *msg_win = newwin(LINES-1, COLS, 0, 0);
WINDOW *input_win = newwin(1, COLS, LINES-1, 0);
scrollok(msg_win, TRUE);

// bufor wprowadzania
char input_buf[MAX_IN] = {0};
int in_len = 0;

// prompt
mvwprintw(input_win, 0, 0, "loracrypt-client> ");
wrefresh(input_win);
wrefresh(msg_win);

while (1) {
// --- 1) obsługa klawiszy użytkownika ---
// ustawiamy timeout = 100 ms, żeby nie blokować wiecznie na wgetch
wtimeout(input_win, 100);
int ch = wgetch(input_win);
if (ch != ERR) {
if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
if (in_len > 0) {
in_len--;
input_buf[in_len] = 0;
}
}
else if (ch == '\n' || ch == '\r') {
// ENTER: wyślij zaszyfrowaną wiadomość
if (in_len > 0) {
// szyfrowanie
unsigned char nonce[NONCE_LEN];
randombytes_buf(nonce, NONCE_LEN);
unsigned char ctext[NONCE_LEN + MAX_PLAINTEXT + MAC_LEN];
memcpy(ctext, nonce, NONCE_LEN);
crypto_secretbox_easy(
ctext + NONCE_LEN,
(unsigned char*)input_buf,
in_len,
nonce,
tx_key
);
uint16_t flen = PK_LEN + NONCE_LEN + in_len + MAC_LEN;
unsigned char hdr[2] = { (uint8_t)(flen>>8), (uint8_t)flen };

// wysyłamy: hdr, my_pk, ctext
write_all(ser, hdr, 2);
write_all(ser, my_pk, PK_LEN);
write_all(ser, ctext, flen - PK_LEN);

// wiadomość echa
wprintw(msg_win, "[You] %s\n", input_buf);
wrefresh(msg_win);
}
// wyczyść bufor i odśwież prompt
in_len = 0;
input_buf[0] = 0;
}
else if (isprint(ch) && in_len < MAX_IN-1) {
input_buf[in_len++] = (char)ch;
input_buf[in_len] = 0;
}
// odrysuj pasek wprowadzania
werase(input_win);
mvwprintw(input_win, 0, 0, "loracrypt-client> %s", input_buf);
wrefresh(input_win);
}

// --- 2) obsługa przychodzącej ramki z serwera ---
fd_set rd;
struct timeval tv = { 0, 0 };
FD_ZERO(&rd);
FD_SET(ser, &rd);
if (select(ser+1, &rd, NULL, NULL, &tv) > 0 && FD_ISSET(ser, &rd)) {
unsigned char hdr[2];
if (read_all(ser, hdr, 2) != 2) break;
uint16_t flen = (hdr[0]<<8) | hdr[1];
if (flen < PK_LEN + NONCE_LEN + MAC_LEN || flen > MAX_FRAME) {
// odrzucamy
unsigned char trash[256];
size_t togo = flen;
while (togo) {
size_t chunk = togo > sizeof(trash) ? sizeof(trash) : togo;
read_all(ser, trash, chunk);
togo -= chunk;
}
continue;
}
// czytamy PK (nieużywane, bo zakładamy tylko od serwera)
unsigned char sender_pk[PK_LEN];
read_all(ser, sender_pk, PK_LEN);
unsigned char encbuf[MAX_FRAME];
size_t enc_len = flen - PK_LEN;
read_all(ser, encbuf, enc_len);

// odszyfrowanie
unsigned char *nonce = encbuf;
unsigned char *cipher = encbuf + NONCE_LEN;
size_t clen = enc_len - NONCE_LEN;
unsigned char plain[MAX_PLAINTEXT+1];
if (crypto_secretbox_open_easy(plain, cipher, clen, nonce, rx_key) == 0) {
// wypisz w msg_win
plain[clen - MAC_LEN] = 0;
wprintw(msg_win, "[Server] %s\n", plain);
wrefresh(msg_win);

// odśwież pasek wprowadzania nad aktualnym input_buf
werase(input_win);
mvwprintw(input_win, 0, 0, "loracrypt-client> %s", input_buf);
wrefresh(input_win);
}
}
}

// --- sprzątanie ---
delwin(msg_win);
delwin(input_win);
endwin();
}

int main(int argc, char *argv[]) {
    if (argc != 3 || (argv[1][1] != 's' && argv[1][1] != 'c')) {
        fprintf(stderr,
            "Usage: %s -s|-c <serial_device>\n"
            " -s server mode, -c client mode\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    int ser = open_serial(argv[2]);

    unsigned char my_pk[PK_LEN], my_sk[SK_LEN], peer_pk[PK_LEN];
    unsigned char rx_key[SESSION_KEY_LEN], tx_key[SESSION_KEY_LEN];

    if (argv[1][1] == 's') {
        printf("*** RUNNING AS SERVER ***\n");
        // server generuje jedną parę kluczy i czeka na handshakes w interactive loop
        if (crypto_kx_keypair(my_pk, my_sk) != 0) {
            fprintf(stderr, "crypto_kx_keypair failed (server)\n"); return 1;
        }
        printf("Server PK: ");
        for (int i=0;i<PK_LEN;i++) printf("%02x", my_pk[i]);
        printf("\n");
        interactive_loop_server(ser, my_pk, my_sk);
    } else {
        printf("*** RUNNING AS CLIENT ***\n");
        handshake_client(ser, my_pk, my_sk, peer_pk, rx_key, tx_key);
        printf("Gotowy do komunikacji zaszyfrowanej!\n");
        interactive_loop_client(ser, my_pk, my_sk, peer_pk, rx_key, tx_key);
    }

    close(ser);
    return 0;
}
