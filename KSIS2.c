#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>


typedef struct response_info {
    char ip[20];
    struct timeval time;
} response_info_t;


typedef enum await_result {
    TIMEOUT,
    AVALIABLE
} await_result_t;


uint16_t icmp_checksum(const void* buf, int length) {
    assert (length % 2 == 0);

    uint16_t sum = 0;
    const uint16_t* ptr = buf;

    while (length > 0) {
        sum += *ptr++;
        length -= 2;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    return ~(sum + (sum >> 16));
}


void init_icmp_packet(struct icmphdr* dest, int seq) {
    assert(dest != NULL);

    dest->type = ICMP_ECHO;
    dest->code = 0;
    dest->un.echo.id = getpid();
    dest->un.echo.sequence = seq;
    dest->checksum = 0;
    dest->checksum = icmp_checksum(dest, sizeof(struct icmphdr));
}


int sequence_number(int ttl, int i) {
    return ttl << 2 | i;
}


int was_recent(int seq, int ttl) {
    return seq >> 2 == ttl;
}


void send_packet(const struct icmphdr* packet, int fd, const struct sockaddr_in* dest) {
    ssize_t sent = sendto(fd, packet, sizeof(struct icmphdr), 0,(struct sockaddr*)dest, sizeof(struct sockaddr_in));

    if (sent == -1) {
        perror("sendto");
        exit(-1);
    }
    assert(sent == sizeof(packet));
}


bool is_valid_ttl_exceeded_packet(const void* buffer, int ttl) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    ssize_t ip_header_size  = 4 * ip_header->ihl;

    struct icmphdr* icmp_header = (struct icmphdr*)((uint8_t*)buffer + ip_header_size);
    int id = icmp_header->un.echo.id;
    int seq = icmp_header->un.echo.sequence;

    return id == getpid() && was_recent(seq, ttl);
}


char* translate_address(const struct sockaddr_in* addr, char buffer[20]) {
    const char* sender_ip = inet_ntop(AF_INET, &addr->sin_addr, buffer, 20);

    if (sender_ip == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    return buffer;
}


void print_unique_responders(response_info_t* responders, int n) {
    for (int i = 0; i < n; i++) {
        const char* ip = responders[i].ip;
        bool unique = true;

        for (int j = 0; j < i; j++) {
            const char* other_ip = responders[j].ip;

            if (strcmp(ip, other_ip) == 0) {
                unique = false;
                break;
            } 
        }

        if (unique) {
            printf("%s ", ip);
        }
    }
}


void update_time(response_info_t* responder, struct timeval* time_left) {
    responder->time.tv_sec  = 1;
    responder->time.tv_usec = 0;
    timersub(&responder->time, time_left, &responder->time);
}


void print_responders_avg_time(response_info_t* responders, int n) {
    uint64_t total_microseconds = 0;
    for (int i = 0; i < n; i++) {
    	uint64_t time = responders[i].time.tv_usec / 1000;
    	printf("%ldms ", time);
        total_microseconds += responders[i].time.tv_usec;
    }

    uint64_t average = total_microseconds / 1000 / 3;
    printf(" Average: %ldms\n", average);    
}


static await_result_t await_packets(int socket_fd, struct timeval* time) { 
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);

    int result = select(socket_fd + 1, &fds, NULL, NULL, time);

    if (result == -1) {
        perror("select");
        exit(EXIT_FAILURE);
    } else if (result == 0) {
        return TIMEOUT;
    }

    return AVALIABLE;
}


static bool receive_packets(int socket_fd, int ttl) {
    int received = 0;

    struct timeval time;
    time.tv_sec  = 1;
    time.tv_usec = 0;

    bool target_responded = false;
    response_info_t responders[3];

    printf("%d. ", ttl);

    while (received < 3) {
        if (await_packets(socket_fd, &time) == TIMEOUT) {
            break;
        }

        struct sockaddr_in sender;
        socklen_t sender_size = sizeof(sender);
        uint8_t buffer[IP_MAXPACKET] = {0};

        ssize_t packet_size = recvfrom(socket_fd, buffer, IP_MAXPACKET, 0, (struct sockaddr*)&sender, &sender_size);

        if (packet_size == -1) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        translate_address(&sender, responders[received].ip);

        struct iphdr* ip_header = (struct iphdr*)buffer;
        ssize_t ip_header_size  = 4 * ip_header->ihl;

        struct icmphdr* icmp_header = (struct icmphdr*)(buffer+ip_header_size);
        int id = icmp_header->un.echo.id;
        int seq = icmp_header->un.echo.sequence;

        if (icmp_header->type == ICMP_ECHOREPLY) {
            if (id != getpid() || !was_recent(seq, ttl)) {
                continue;
            }
            target_responded = true;
        } else if (icmp_header->type == ICMP_TIME_EXCEEDED) {
            void* payload = (uint8_t*)icmp_header + sizeof(struct icmphdr);
            if (!is_valid_ttl_exceeded_packet(payload, ttl)) {
                continue;
            }
        } else {
            continue;
        }

        update_time(&responders[received], &time);
        received++;
    }

    print_unique_responders(responders, received);

    if (received == 0) {
        printf("*\n");
    } else if (received < 3) {
        printf("???\n");
    } else {
        print_responders_avg_time(responders, received);
    }

    return target_responded;
}


void traceroute(const struct sockaddr_in* dest, int socket_fd) {
    for (int ttl = 1; ttl <= 30; ttl++) {
        for (int i = 0; i < 3; i++) {
            struct icmphdr packet;
            init_icmp_packet(&packet, sequence_number(ttl, i));
            
            int ttl_set = setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

            if (ttl_set == -1) {
                perror("setsockopt");
                exit(EXIT_FAILURE);
            }            
            
            send_packet(&packet, socket_fd, dest);
        }

        if (receive_packets(socket_fd, ttl)) {
            return;
        }
    }
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./traceroute [address]\n");
        return EXIT_FAILURE;
    }

    const char* address = argv[1];

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, address, &addr.sin_addr) == 0) {
        fprintf(stderr, "inet_pton: '%s' is not a valid network address!\n", address);
        return EXIT_FAILURE;
    }

    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    traceroute(&addr, socket_fd);

    close(socket_fd);
    return 0;
}
