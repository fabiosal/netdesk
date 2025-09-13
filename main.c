#define _DEFAULT_SOURCE

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  setbuf(stdout, NULL); // disable buffer on stdout
  char proc_net_tcp_line[200];
  FILE *fd;
  int i = 0;

  enum connection_type {
    TCP,
    TCP6,
    UDP,
    UDP6
  };

  typedef struct {
    char pid[12];
    char comm[20];
  } process;

  typedef struct {
    char *ip;
    char *port;
  } address;

  typedef struct {
    char *inode;
    enum connection_type type;
    address local;
    address remote;
    process *proc;
  } connection;

  connection *connections[300]; // array of 300 pointers to conncection
  int number_of_connections = 0;

  /*printf("\033[2J");*/
  /*printf("\033[0H");*/
  /*printf("\033[1;31m"); //set colors*/
  /*printf("NetDesk");*/

  fd = fopen("/proc/net/tcp", "r");

  while (fgets(proc_net_tcp_line, 200, fd)) {
    if (i == 0) {
      i++;
      continue;
    }

    char *token;
    int j = 0;
    connection *a = (connection *)malloc(sizeof(connection));
    a->type = TCP;

    token = strtok(proc_net_tcp_line, " :"); // split on space and colon

    while (token != NULL) {
      /*printf("%s\n", token);*/
      if (j == 1) {
        a->local.ip = (char *)malloc(strlen(token) + 1);
        strcpy(a->local.ip, token);
      } else if (j == 2) {
        a->local.port = (char *)malloc(strlen(token) + 1);
        strcpy(a->local.port, token);
      } else if (j == 3) {
        a->remote.ip = (char *)malloc(strlen(token) + 1);
        strcpy(a->remote.ip, token);
      } else if (j == 4) {
        a->remote.port = (char *)malloc(strlen(token) + 1);
        strcpy(a->remote.port, token);
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

  int z;
  for (z = 0; z < number_of_connections; z++) {
    printf("n: %d\nlocal:%s %s\nremote:%s %s\ninode:%s\n\n", z,
           connections[z]->local.ip, connections[z]->local.port,
           connections[z]->remote.ip, connections[z]->remote.port,
           connections[z]->inode);
  }

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
    /*printf("full path: %s\n", concat_path);*/
    struct stat st;
    if (stat(concat_path, &st) != 0) {
      continue;
    }
    if (S_ISDIR(st.st_mode) && isdigit(d->d_name[0])) {
      /*printf("%s \n", concat_path);*/

      char concat_path2[100];
      strcpy(concat_path2, concat_path);
      strcat(concat_path2, "/fd/");
      /*printf("%s \n", concat_path2);*/

      DIR *dir_process = opendir(concat_path2);
      if (!dir_process)
        continue;

      struct stat st2;
      struct dirent *d2;
      while ((d2 = readdir(dir_process)) != NULL) {
        if (stat(concat_path2, &st2) != 0) {
          continue;
        }
        /*printf("%s %c\n", d2->d_name,d2->d_type);*/
        if (S_ISDIR(st2.st_mode) && isdigit(d2->d_name[0])) {

          /*printf("%s \n", d2->d_name);*/
          /*printf("%s \n", concat_path);*/

          char concat_path3[100];
          strcpy(concat_path3, concat_path2);
          strcat(concat_path3, d2->d_name);
          /*printf("%s \n", concat_path3);*/

          char buf[100];
          ssize_t size;
          size = readlink(concat_path3, buf, 100);
          buf[size] = '\0';
          /*int z;*/
          /*printf("### ");*/
          /*for (z = 0; z < size; z++) {*/
          /*printf("%c", buf[z]);*/
          /*}*/
          /*printf("\n");*/

          if (strstr(buf, "socket\0") == NULL) {
            /*printf("NOT A SOCKET\n"); */
            continue;
          }

          /*printf("%s\n", pos);*/
          /*if (pos == NULL) {*/
          /*continue;*/
          /*}*/

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

            /*printf("%c", result[strlen(result)]);*/

            /*printf("%s - %s | %lu - %lu \n", buf, result, strlen(buf),
             * strlen(result));*/
            if (strcmp(result, buf) == 0) {
              printf("PROCESS: %s \tINODE: %s \n", d->d_name,
                     connections[x]->inode);
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
}

// todo
// the list of tcp connection should contain only entry different from listening status ?
