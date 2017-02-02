default:
	gcc -pthread -lmcrypt -o client client.c
	gcc -pthread -lmcrypt -o server server.c
client:
	gcc -pthread -lmcrypt -o client client.c
server:
	gcc -pthread -lmcrypt -o server server.c
clean:
	$(RM) client server *.o *~ *.out 
dist:
	tar -cvzf lab1b-404428077.tar.gz client.c server.c README Makefile my.key
