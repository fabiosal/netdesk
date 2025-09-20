#include <asm-generic/int-ll64.h>
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// for socket comunication
#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/socket.h>

// for sock_diag netlink subsystem
#include <linux/sock_diag.h>
/*#include <linux/unix_diag.h> [> for UNIX domain sockets <]*/
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */
#include <linux/tcp.h>

// in order to manipulate rtnetlink messages
// see https://man7.org/linux/man-pages/man3/rtnetlink.3.html
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#ifndef TCPF_ALL

/*
 * Can't find header file that contains the following definitions of tcp states.
 * Should ne in <netinet/tcp_states.h> is not part of glibc’s “standard”
 * includes like <netinet/tcp.h>. It’s provided by the linux-headers package
 * (the UAPI export from your kernel). If your system doesn’t have
 * <netinet/tcp_states.h> try to update linux headers
 */
typedef enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING, /* Now a valid state */
  TCP_NEW_SYN_RECV,
  TCP_MAX_STATES /* Leave at the end! */
} tcp_status;

#define TCPF_ESTABLISHED (1 << TCP_ESTABLISHED)
#define TCPF_SYN_SENT (1 << TCP_SYN_SENT)
#define TCPF_SYN_RECV (1 << TCP_SYN_RECV)
#define TCPF_FIN_WAIT1 (1 << TCP_FIN_WAIT1)
#define TCPF_FIN_WAIT2 (1 << TCP_FIN_WAIT2)
#define TCPF_TIME_WAIT (1 << TCP_TIME_WAIT)
#define TCPF_CLOSE (1 << TCP_CLOSE)
#define TCPF_CLOSE_WAIT (1 << TCP_CLOSE_WAIT)
#define TCPF_LAST_ACK (1 << TCP_LAST_ACK)
#define TCPF_LISTEN (1 << TCP_LISTEN)
#define TCPF_CLOSING (1 << TCP_CLOSING)

#define TCPF_ALL                                                               \
  (TCPF_ESTABLISHED | TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_FIN_WAIT1 |         \
   TCPF_FIN_WAIT2 | TCPF_TIME_WAIT | TCPF_CLOSE | TCPF_CLOSE_WAIT |            \
   TCPF_LAST_ACK | TCPF_LISTEN | TCPF_CLOSING)
#endif

/*
 * The following function convert ip address:
 * from little endian hex form -> 3600007F
 * to standard text presentation -> 127.0.0.54
 */
void address_converter(char *lehf, char *stp) {
  // this is working for ipv4 addresses
  int i;
  char buf[3];
  stp[0] = '\0';

  for (i = 6; i >= 0; i = i - 2) {
    char octet[3];
    memcpy(octet, &lehf[i], 2);
    octet[2] = '\0';
    short a = strtol(octet, NULL, 16);
    sprintf(buf, "%hu", a);
    if (i < 6) {
      strcat(stp, ".");
    }
    strcat(stp, buf);
  }
  strcat(stp, "\0");
}

int main(int argc, char *argv[]) {
  setbuf(stdout, NULL); // disable buffer on stdout
  char proc_net_tcp_line[200];
  FILE *fd;
  int i = 0;
  struct timespec time_sample;

  enum connection_type { TCP, TCP6, UDP, UDP6 };

  typedef struct {
    char pid[12];
    char comm[25];
  } process;

  typedef struct {
    char *ip;
    int port;
  } address;

  typedef struct {
    __u64 byte_sent;
    __u64 byte_received;
    struct timespec time;
  } trasmission;

  typedef struct {
    char *inode;
    enum connection_type type;
    address local;
    address remote;
    tcp_status status;
    process *proc;
    trasmission first_sample;
    trasmission second_sample;
  } connection;

  connection *connections[300]; // array of 300 pointers to conncection
  int number_of_connections = 0;

  /*printf("\033[2J");*/
  /*printf("\033[0H");*/
  /*printf("\033[1;31m"); //set colors*/
  /*printf("NetDesk");*/

  while (1) {
    number_of_connections = 0;
    fd = fopen("/proc/net/tcp", "r");

    i = 0;
    while (fgets(proc_net_tcp_line, 200, fd)) {
      if (i == 0) {
        i++;
        continue;
      }

      char *token;
      int j = 0;
      connection *a = (connection *)malloc(sizeof(connection));
      if (!a) {
        perror("malloc error");
        exit(EXIT_FAILURE);
      }
      a->proc = NULL;
      a->type = TCP;

      token = strtok(proc_net_tcp_line, " :"); // split on space and colon

      while (token != NULL) {
        /*printf("%s\n", token);*/
        if (j == 1) {
          a->local.ip = (char *)malloc(16);
          address_converter(token, a->local.ip);
        } else if (j == 2) {
          a->local.port = (int)strtol(token, NULL, 16);
        } else if (j == 3) {
          a->remote.ip = (char *)malloc(16);
          address_converter(token, a->remote.ip);
        } else if (j == 4) {
          a->remote.port = (int)strtol(token, NULL, 16);
        } else if (j == 5) {
          a->status = (int)strtol(token, NULL, 16);
        } else if (j == 13) {
          a->inode = (char *)malloc(strlen(token) + 1);
          strcpy(a->inode, token);
        }
        token = strtok(NULL, " :"); // continue splitting
        j++;
      }

      // add connection struct to connections array
      connections[number_of_connections++] = a;
    }

    fclose(fd);

    // find inodes between process fds
    DIR *dir_main = opendir("/proc/");
    assert(dir_main != NULL);
    /*char concat_path[100] = "\0";*/
    struct dirent *d;
    char concat_path[80];
    while ((d = readdir(dir_main)) != NULL) {
      /*printf("%lu %s \n", (unsigned long)d->d_ino, d->d_name);*/

      strcpy(concat_path, "/proc/");
      strcat(concat_path, d->d_name);
      struct stat st;
      if (stat(concat_path, &st) != 0) {
        continue;
      }
      if (S_ISDIR(st.st_mode) && isdigit(d->d_name[0])) {

        char concat_path2[100];
        strcpy(concat_path2, concat_path);
        strcat(concat_path2, "/fd/");

        DIR *dir_process = opendir(concat_path2);
        if (!dir_process)
          continue;

        struct stat st2;
        struct dirent *d2;
        while ((d2 = readdir(dir_process)) != NULL) {
          if (stat(concat_path2, &st2) != 0) {
            continue;
          }
          if (S_ISDIR(st2.st_mode) && isdigit(d2->d_name[0])) {

            char concat_path3[100];
            strcpy(concat_path3, concat_path2);
            strcat(concat_path3, d2->d_name);

            char buf[100];
            ssize_t size;
            size = readlink(concat_path3, buf, 100);
            if (size == -1) {
              continue;
            }
            buf[size] = '\0';

            if (strstr(buf, "socket\0") == NULL) {
              continue;
            }

            int x;
            for (x = 0; x < number_of_connections; x++) {
              char part1[] = "socket:[";
              /*char *part2;*/
              char part3[] = "]";

              size_t len = strlen(part1) + strlen(connections[x]->inode) +
                           strlen(part3) + 1;
              // allocate memory
              char *result = malloc(len);
              if (!result) {
                perror("malloc failed");
                return 1;
              }

              // build the string
              strcpy(result, part1);                 // copy first
              strcat(result, connections[x]->inode); // append second
              strcat(result, part3);                 // append third

              if (strcmp(result, buf) == 0) {
                process *p = (process *)malloc(sizeof(process));
                strcpy(p->pid, d->d_name);
                connections[x]->proc = p;

                char comm_filepath[60];
                strcpy(comm_filepath, "/proc/");
                strcat(comm_filepath, d->d_name);
                strcat(comm_filepath, "/comm");
                FILE *cfd = fopen(comm_filepath, "r");
                if (cfd != NULL) {
                  fgets(connections[x]->proc->comm, 25, cfd);
                  connections[x]
                      ->proc->comm[strlen(connections[x]->proc->comm) - 1] =
                      '\0';

                } else {
                  strcpy(connections[x]->proc->comm, "xxx\0");
                }

                fclose(cfd);

                /*printf("PROCESS: %s \tINODE: %s \tCOMMAND: %s \n",
                 * d->d_name,*/
                /*connections[x]->inode, connections[x]->proc->comm);*/
                free(result);
                break;
              }

              free(result);
            }
          }
        }

        closedir(dir_process);
      }
    }
    closedir(dir_main);

    /*printf(*/
    /*"n\tlocal\tport\tremote\tport\ts_type\tinode\tstatus\tpid\tcommand\n");*/
    int z;
    /*for (z = 0; z < number_of_connections; z++) {*/
    /*printf("%d\t%s\t%d\t%s\t%d\t%u\t%s\t%d", z, connections[z]->local.ip,*/
    /*connections[z]->local.port, connections[z]->remote.ip,*/
    /*connections[z]->remote.port, connections[z]->type,*/
    /*connections[z]->inode, connections[z]->status);*/
    /*[>printf("\nz: %d\tpointer proc: %p\n", z, connections[z]->proc);<]*/
    /*if (connections[z]->proc != NULL) {*/
    /*printf("\t%s\t%s", connections[z]->proc->pid,*/
    /*connections[z]->proc->comm);*/
    /*}*/
    /*printf("\n");*/
    /*}*/

    // retrieveing information about specific sockets from the kernel
    /*for (z = 0; z < number_of_connections; z++) {*/
    /*if (connections[z]->proc != NULL) {*/
    /*if (strcmp(connections[z]->proc->comm, "spotify") == 0) {*/
    /*printf("%d\n", z);*/
    /*break;*/
    /*}*/
    /*}*/
    /*}*/
    /*if (z == number_of_connections) {*/
    /*puts("process not exists");*/
    /*exit(0);*/
    /*}*/
    /*z = 31;*/

    int sfd;
    if ((sfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) == -1) {
      perror("during socket creation: ");
      return EXIT_FAILURE;
    }

    int j = 0;
    while (j++ < 2) {
      struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};

      // Build netlink header + request
      // see https://man7.org/linux/man-pages/man7/netlink.7.html
      char buf[8192];
      struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
      nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2));
      nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
      nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
      nlh->nlmsg_seq = 12345;
      nlh->nlmsg_pid = 0;

      // see https://man7.org/linux/man-pages/man7/sock_diag.7.html
      /*
      struct inet_diag_sockid id;
      id.idiag_sport = connections[z]->local.port;
      inet_pton(AF_INET, connections[z]->local.ip, id.idiag_src);
      id.idiag_dport = connections[z]->remote.port;
      inet_pton(AF_INET, connections[z]->local.ip, id.idiag_dst);
      id.idiag_if = 0;
      */

      /*struct inet_diag_req_v2 req;*/
      struct inet_diag_req_v2 *req = (struct inet_diag_req_v2 *)NLMSG_DATA(nlh);
      memset(req, 0, sizeof(*req));
      req->sdiag_family = AF_INET;
      req->sdiag_protocol = IPPROTO_TCP;
      req->idiag_ext = (1 << (INET_DIAG_INFO - 1));
      req->pad = 0;
      req->idiag_states = TCPF_ALL; // filter sockets by status
      /*req->id = id;*/

      struct iovec iov = {nlh, nlh->nlmsg_len};
      struct msghdr msg = {&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0};

      if (sendmsg(sfd, &msg, 0) < 0) {
        perror("sendmsg");
        return 1;
      }

      // Read responses
      int goon = 1;
      while (goon) {
        int len = recv(sfd, buf, sizeof(buf), 0);
        if (len <= 0)
          break;

        clock_gettime(CLOCK_REALTIME, &time_sample);
        for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
             nlh = NLMSG_NEXT(nlh, len)) {
          if (nlh->nlmsg_type == NLMSG_DONE) {
            goon = 0;
            break;
          }
          if (nlh->nlmsg_type == NLMSG_ERROR) {
            fprintf(stderr, "netlink error\n");
            goon = 0;
            break;
          }
          struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);
          /*printf("Socket: src port %u, dst port %u, state %u, inode: %d\n",*/
          /*ntohs(diag->id.idiag_sport), ntohs(diag->id.idiag_dport),*/
          /*diag->idiag_state, diag->idiag_inode);*/
          /*printf("%d\n", diag->id.idiag_if);*/
          /*printf("%d\n", diag->idiag_family);*/
          /*printf("%d\n", diag->idiag_uid);*/
          /*printf("%d\n",diag->tcp_info->tcpi_bytes_acked);*/

          int rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag));
          // see https://man7.org/linux/man-pages/man7/rtnetlink.7.html
          struct rtattr *attr = (struct rtattr *)(diag + 1);

          // Walk attributes
          for (; RTA_OK(attr, rtalen); attr = RTA_NEXT(attr, rtalen)) {
            if (attr->rta_type == INET_DIAG_INFO) {

              /*
               * Relevant fields on tcpi structure
               * tcpi_bytes_acked: total bytes ACKed (delivered).
               * tcpi_bytes_received: total bytes received.
               * tcpi_bytes_sent: total bytes sent, including retransmissions.
               * tcpi_bytes_retrans: total retransmitted bytes.
               * tcpi_delivery_rate: estimated delivery rate in bytes/sec.
               */
              struct tcp_info *tcpi = (struct tcp_info *)RTA_DATA(attr);

              /*printf("  RTT: %u usec, retrans: %u, cwnd: %u\n",
               * tcpi->tcpi_rtt,*/
              /*tcpi->tcpi_total_retrans, tcpi->tcpi_snd_cwnd);*/

              // Check if extended fields exist ?!
              if (len >= offsetof(struct tcp_info, tcpi_bytes_acked) +
                             sizeof(tcpi->tcpi_bytes_acked)) {
                /*printf("  Bytes acked: %llu, Bytes received: %llu\n",*/
                /*(unsigned long long)tcpi->tcpi_bytes_acked,*/
                /*(unsigned long long)tcpi->tcpi_bytes_received);*/

                for (z = 0; z < number_of_connections; z++) {
                  if (atoi(connections[z]->inode) == diag->idiag_inode) {
                    /*printf("##########PIPPO con j:%d\n",j);*/
                    if (j == 1) {
                      memcpy(&(connections[z]->first_sample.time), &time_sample,
                             sizeof time_sample);
                      connections[z]->first_sample.byte_sent =
                          tcpi->tcpi_bytes_sent;
                      connections[z]->first_sample.byte_received =
                          tcpi->tcpi_bytes_received;
                    } else if (j == 2) {
                      memcpy(&(connections[z]->second_sample.time),
                             &time_sample, sizeof time_sample);
                      connections[z]->second_sample.byte_sent =
                          tcpi->tcpi_bytes_sent;
                      connections[z]->second_sample.byte_received =
                          tcpi->tcpi_bytes_received;
                    }
                  }
                }
              }
            }
          }
        }
      }

      struct timespec time;
      struct timespec rem;
      time.tv_sec = 2;
      time.tv_nsec = 0;

      puts("\n\n");
      if (nanosleep(&time, &rem) == -1) {
        perror("sleep time not respected");
        break;
      }
    }

    int seconds = connections[0]->second_sample.time.tv_sec -
                  connections[0]->first_sample.time.tv_sec;
    printf("second: %d\n", seconds);

    printf(
        "n\tlocal\tport\tremote\tport\ts_type\tinode\tstatus\tpid\tcommand\n");
    for (z = 0; z < number_of_connections; z++) {
      printf("%d\t%s\t%d\t%s\t%d\t%u\t%s\t%d", z, connections[z]->local.ip,
             connections[z]->local.port, connections[z]->remote.ip,
             connections[z]->remote.port, connections[z]->type,
             connections[z]->inode, connections[z]->status);
      if (connections[z]->proc != NULL) {
        printf("\t%s\t%s\t", connections[z]->proc->pid,
               connections[z]->proc->comm);
      }

      printf("%llu B/sec\t", (connections[z]->second_sample.byte_received -
                              connections[z]->first_sample.byte_received) /
                                 seconds);
      printf("%llu B/sec\t", (connections[z]->second_sample.byte_sent -
                              connections[z]->first_sample.byte_sent) /
                                 seconds);
      printf("\n");
    }

    close(sfd);

    for (z = 0; z < number_of_connections; z++) {
      if (connections[z]->proc != NULL) {
        free(connections[z]->proc);
      }
      if (connections[z]->inode != NULL) {
        free(connections[z]->inode);
      }
      if (connections[z]->local.ip != NULL) {
        free(connections[z]->local.ip);
      }
      if (connections[z]->remote.ip != NULL) {
        free(connections[z]->remote.ip);
      }
      if (connections[z] != NULL) {
        free(connections[z]);
      }
    }
  }
}

// todo
// the list of tcp connection should contain only entry different from listening
// improve precision of transfer rate not considering only seconds between two
// sample collect data also for ipv6 sockets
