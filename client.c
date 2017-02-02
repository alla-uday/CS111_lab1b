#include <fcntl.h>
#include <mcrypt.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/wait.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>


struct termios original_attributes;
char* logname;
int flag;
int fd;
int encrypt;
int ENCRYPTMESSAGE=1;
int DECRYPTMESSAGE=0;
char* key="";
struct arg_struct {
  int src;
  int dst;
};
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
void error(char *msg)
{
  perror(msg);
  exit(0);
}
void  handler(int sig)
{
  close(fd);
  exit(0);
}

void orig_mode(void)
{
  tcsetattr(STDIN_FILENO, TCSANOW, &original_attributes);
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
  struct arg_struct *args = (struct arg_struct *)arguments;
  char c;char d;int x;
  while(1){
    if(args->dst>args->src){
      x=read(args->src, &c, 1);
      if(x<=0){
	close(args->dst);
	exit(1);
      }
      if(c=='\004'){
	close(args->dst);
	exit(0);
      }
      else{
	if(encrypt==1){
	  d=c;
	  char* message ="";
	  message = appendChar(message,c);
	  int mlen=strlen(message);
	  int ret = encryptmsg(message,key,mlen,ENCRYPTMESSAGE);
	  c=message[0];
	}
	if(flag==1){
	  char p='\n';
	  char* rcc = "SENT 1 byte: ";
	  rcc=appendChar(rcc,c);
       	  write(fd, rcc,  sizeof(char)*strlen(rcc));
	  write(fd,&p ,1);
	  
	}
	if(encrypt==1){
	  if(d=='\r' || d== '\n'){
	    //char temp ='\n';
	    write(args->dst, &c, 1);
	    char temp='\r';
	    write(STDOUT_FILENO, &temp, 1);
	    temp='\n';
	    write(STDOUT_FILENO, &temp, 1);
	    
	  }
	  else{
	    write(args->dst, &c, 1);
	    write(STDOUT_FILENO, &d, 1);
	  }
	}
	else{
	  if(c=='\r' || c== '\n'){
	    char temp1 ='\n';
	    write(args->dst, &temp1, 1);
	    char temp='\r';
	    write(STDOUT_FILENO, &temp, 1);
	    temp='\n';
	    write(STDOUT_FILENO, &temp, 1);
	  }
	  else{
	    write(args->dst, &c, 1);
	    write(STDOUT_FILENO, &c, 1);
	  }
	}
      }
    }
    else{
      x=read(args->src, &c, 1);
      if(x<=0){
	close(args->src);
	exit(1);
      }
      else{
	if(flag==1){
	  char p = '\n';
	  char* rbb = "RECEIVED 1 byte: ";
	  rbb=appendChar(rbb,c);
	  write (fd, rbb,  sizeof(char)*strlen(rbb));
	  write(fd,&p ,1);
	}
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
  }
}
int main(int argc, char **argv)
{
  int sockfd, portnumber,logFlag, n;

  struct sockaddr_in serv_addr;
  struct hostent *server;
  char* logfile;
  int opt=0;
  int longIndex=0;
  static const char *optString = "ple";
  static struct option long_options[] = {
    {"port", required_argument, NULL, 'p'},
    {"log", required_argument, NULL,'l'},
    {"encrypt", no_argument, NULL,'e'},
    {NULL, no_argument, NULL, 0}
  };
  opt = getopt_long( argc, argv, optString, long_options, &longIndex );
  while( opt!= -1) {
    switch( opt ) {
    case 'p':
      portnumber=atoi(optarg);
      break;
    case 'l':
      logfile=optarg;
      logname=logfile;
      logFlag=1;
      flag=1;
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
  fd=sockfd;
  char *host_name;
  host_name="localhost";
  server = gethostbyname(host_name);
  if (server == NULL) {
    fprintf(stderr,"ERROR, no such host\n");
    exit(0);
  }
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,	(char *)&serv_addr.sin_addr.s_addr,server->h_length);
  serv_addr.sin_port = htons(portnumber);
  if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
    error("ERROR connecting");
  if(flag==1)
    fd  =  open(logname, O_WRONLY | O_CREAT| O_TRUNC, 0644);
  if(encrypt==1){
    int keyfd=open("my.key", O_RDONLY, 0);
    char i;
    while (read(keyfd, &i, 1) > 0) {
      key = appendChar(key,i);
    }
    close(keyfd);
  }
  no_echo_mode();
  pthread_t tid1,tid2;
  struct arg_struct args1;
  struct arg_struct args2;
  args1.src=STDIN_FILENO;
  args1.dst=sockfd;
  args2.src=sockfd;
  args2.dst=STDOUT_FILENO;
  pthread_create(&tid1, NULL, &read_all, (void *)&args1);
  pthread_create(&tid2, NULL, &read_all, (void *)&args2);
  pthread_join(tid1,NULL);
  pthread_join(tid2,NULL);
  close(fd);
  exit(0);
}
