#include <fcntl.h>
#include <mcrypt.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libgen.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <pthread.h>

void error(char *msg)
{
  perror(msg);
  exit(1);
}

struct termios original_attributes;
int childPid;
int fd;
int input_pipe[2];
int output_pipe[2];
int encrypt;
int ENCRYPTMESSAGE=1;
int DECRYPTMESSAGE=0;
char* key="";
struct arg_struct {
  int src;
  int dst;
};

void orig_mode(void)
{
  tcsetattr(STDIN_FILENO, TCSANOW, &original_attributes);
}

void sigPipehandler()
{
  kill(childPid,SIGKILL);
  close(fd);
  exit(2);
}
char *appendChar(const char *orig, char c)
{
  size_t origlen = strlen(orig);
  char *newstr = malloc(origlen + 2);
  strcpy(newstr, orig);
  newstr[origlen] = c;
  newstr[origlen + 1] = '\0';
  return newstr;
}

int encryptmsg(char *str,char *mykey,int len,int determine)
{
  char *key;
  char *IV;
  int sizeofkey = 16;
  key = calloc(1,sizeofkey);
  MCRYPT td = mcrypt_module_open("twofish",NULL,"cfb",NULL);
  int size = mcrypt_enc_get_iv_size(td);
  IV = malloc(size);
  int i;
  for(i=0;i<size;i++)
    IV[i] = 1;

  memmove(key,mykey,strlen(mykey));
  i = mcrypt_generic_init(td, key, sizeofkey, IV);
  if(determine == ENCRYPTMESSAGE)
    i = mcrypt_generic(td,str,len);

  if(determine == DECRYPTMESSAGE)
    mdecrypt_generic(td,str,len);

  mcrypt_generic_end(td);
  return len;
}

void no_echo_mode(void)
{
  struct termios tattributes;

  //Save the original attributes for restoring to original mode later
  if (tcgetattr (STDIN_FILENO, &original_attributes) < 0)
    perror("tcsetattr()");
  // tcgetattr (STDIN_FILENO, &original_attributes);
  atexit(orig_mode);

  //checking to see if stdin is a terminal
  if(isatty (STDIN_FILENO)==0)
    {
      fprintf (stderr, "ERROR:stdin not a terminal.\n");
      exit (EXIT_FAILURE);
    }

  //Setting the new terminal modes
  tcgetattr (STDIN_FILENO, &tattributes);
  tattributes.c_lflag = tattributes.c_lflag &  ~(ICANON|ECHO);
  tattributes.c_cc[VMIN] = 1;
  tattributes.c_cc[VTIME] = 0;
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &tattributes);
}

void *read_all(void *arguments) {
  signal(SIGPIPE, sigPipehandler);
  struct arg_struct *args = (struct arg_struct *)arguments;
  char c;int x;
  while(1){
    if(args->dst>args->src){
      x=read(args->src, &c, 1);
      if(x<=0){
	close(fd);
	kill(childPid,SIGKILL);
	exit(1);
	break;
      }
       else{
	if(encrypt==1){
	  char* message="";
	  message = appendChar(message,c);
	  int mlen=strlen(message);
	  int ret = encryptmsg(message,key,mlen,DECRYPTMESSAGE);
	  c=message[0];
	}
	write(args->dst, &c, 1);
      }
    }
    else{
      x=read(args->src, &c, 1);
      if(x<=0){
	close(fd);
	kill(childPid,SIGKILL);
	exit(2);
      }
      else{
	if(encrypt==1){
	  char* message ="";
	  message = appendChar(message,c);
	  int mlen=strlen(message);
	  int ret = encryptmsg(message,key,mlen,ENCRYPTMESSAGE);
	  c=message[0];
      	}
	write(args->dst, &c, 1);
      }
    }
  }
}

int main(int argc, char** argv) {
  int sockfd, newsockfd, portnumber, clilen;
  struct sockaddr_in serv_addr, cli_addr;
  int opt=0;
  int longIndex=0;
  static const char *optString = "pe";
  static struct option long_options[] = {
    {"port", required_argument, NULL, 'p'},
    {"encrypt", no_argument, NULL,'e'},
    {NULL, no_argument, NULL, 0}
  };
  opt = getopt_long( argc, argv, optString, long_options, &longIndex );
  while( opt!= -1) {
    switch( opt ) {
    case 'p':
      portnumber=atoi(optarg);
      //      printf("%d\n", portnumber);
      break;
    case 'e':
      encrypt=1;
      break;
    default:
      /* You won't actually get here. */
      exit(4);
      break;
    }
    opt = getopt_long( argc, argv, optString, long_options, &longIndex );
  }
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portnumber);
  if (bind(sockfd, (struct sockaddr *) &serv_addr,
	   sizeof(serv_addr)) < 0)
    error("ERROR on binding");
  listen(sockfd,5);
  clilen = sizeof(cli_addr);
  newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
  fd=newsockfd;
  if (newsockfd < 0)
    error("ERROR on accept");
  if(encrypt==1){
    int keyfd=open("my.key", O_RDONLY, 0);
    char i;
    while (read(keyfd, &i, 1) > 0) {
      key = appendChar(key,i);
    }
    close(keyfd);
  }
  
  no_echo_mode();
  pipe(input_pipe);
  pipe(output_pipe);
  pid_t rc = fork();
  if (rc < 0) { // fork failed; exit
    fprintf(stderr, "fork error\n");
    exit(1);
  }
  else if (rc  == 0) {
    // child process
    close(input_pipe[1]);
    close(output_pipe[0]);
    dup2(input_pipe[0], STDIN_FILENO);
    dup2(output_pipe[1], STDOUT_FILENO);
    dup2(output_pipe[1], STDERR_FILENO);
    // exec the given program
    char *myargs[2];
    myargs[0] = strdup("/bin/bash");
    myargs[1]=NULL;
    if (execvp(myargs[0] ,myargs ) == -1) {
      perror("failed to start subprocess");
      return EXIT_FAILURE;
    }
  }
  childPid=rc;
  pthread_t tid1,tid2;
  struct arg_struct args1;
  struct arg_struct args2;
  args1.src=newsockfd;
  args1.dst=input_pipe[1];
  args2.src=output_pipe[0];
  args2.dst=newsockfd;

  // parent process
  close(input_pipe[0]);
  close(output_pipe[1]);
  pthread_create(&tid1, NULL, &read_all, (void *)&args1);
  pthread_create(&tid2, NULL, &read_all, (void *)&args2);
  pthread_join(tid1,NULL);
  pthread_join(tid2,NULL);
  close(input_pipe[1]);
  fflush(stdout);
  close(output_pipe[0]);
  exit(0);
  
}
