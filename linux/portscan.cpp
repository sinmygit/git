#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <time.h>
#include <errno.h>

#include <sys/select.h>
#include <arpa/inet.h>

#include <unistd.h>

#include <netdb.h>
#include <ctype.h>


u_long gipbeg,gipend,gipcur;
//HFILE ghf;
pthread_mutex_t gcse;
pthread_mutex_t gcseip;
int gtimeout;
unsigned short gptmd,gptbeg,gptsz;
unsigned short gprot[10];

int mystrlen(char *str)
{
	int len = 0;
	while(*str++!='\0'){len++;}
	return len;
}

int myatoi(char *sin)
{
	int nb = 0;
	while(*sin<='9'&&*sin>='0')
	{
		nb*=10;
		nb+=(*sin - '0');
		sin++;
	}
	return nb;
}

char *myitoa(int nb)
{
	static char sret[11];

	int n=0;
	int i=9;
	do
	{
		n=nb%10;
		sret[i]='0'+n;
		i--;
	}
	while(nb/=10);

	return &sret[i+1];
}


/*
void myfilewrite(char* sout)
{
	u_long dd;
	//WriteFile((HANDLE)ghf,sout,mystrlen(sout),&dd,NULL);
}*/
void getprotfromcl(char* str)
{
	char *stmp = str;
	while(*str++!='\0')
	{
		if(*str=='-')
		{
			gptmd = 1;
			gptbeg=myatoi(stmp);
			while(*stmp++!='-'){};
			gptsz=myatoi(stmp)-gptbeg;
			return;
		}
	}
	int i=0;
	gptmd = 2;
	while(*stmp!='\0')
	{
		gprot[i]=myatoi(stmp);
		i++;
		if(i>9)
			break;
		while(*stmp++!=','&&*stmp!='\0'){};
	}
}

int getprot(unsigned short &prot)
{
	static unsigned short pos = 0;
	int ret=0;
	if(gptmd==1)
	{
		 if(pos<=gptsz)
		 {
			 ret = 0;
		 }
		 else
		 {
			 pos = 0;
			 ret = 1;
		 }
		 prot = gptbeg+pos++;
		 return ret;
	}
	else if(gptmd == 2)
	{
		if(gprot[pos]!=0)
		{
			ret = 0;
		}
		else
		{
			pos = 0;
			ret = 1;
		}
		prot = gprot[pos++];
		return ret;
	}
	return 0;
}


int getip(u_long &ip,unsigned short &prot)
{
	int ret=1;
	pthread_mutex_lock(&gcseip);
	if(gipcur>gipend)
		ret = 0;
	else
	{
		gipcur += getprot(prot);
		if(!((gipcur+1)&0xff))
			gipcur+=2;
		if(gipcur>gipend)
			ret = 0;
		ip=gipcur;
	}
	pthread_mutex_unlock(&gcseip);
	return ret;
}


void saveip(u_long ip,unsigned short prot)
{
	char *sip,*sprot;
	in_addr addr;
	memcpy(&addr,&ip,4);
	pthread_mutex_lock(&gcse);
	sip = inet_ntoa(addr);
	sprot=myitoa(prot);
	//myfilewrite(sip);
	//myfilewrite(" ");
	//myfilewrite(sprot);
	//myfilewrite("\r\n");
	printf(sip);
	printf(" ");
	printf(sprot);
	printf("\r\n");
	pthread_mutex_unlock(&gcse);
}

int checkipprot(u_long ip,int prot,int timeout)
{
	int ret;
	socklen_t len = sizeof(int);
	int error=-1;
	int sc;

	sockaddr_in addr;

	//u_long ul;
	timeval time;
	fd_set r;


	sc = socket(AF_INET,SOCK_STREAM,0);
	if(sc<=0)
		return sc;

	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(INADDR_ANY);
	addr.sin_port=htons(0);
	ret = bind(sc,(sockaddr *)&addr,sizeof(addr));
	if(ret <0)
		goto CleanUp;

	addr.sin_addr.s_addr = ntohl(ip);
	addr.sin_port = htons(prot);

	//ret = ioctlsocket(sc, FIONBIO, &ul);
	ret=fcntl(sc,F_SETFL, O_NONBLOCK);
	if(ret <0)
		goto CleanUp;

	ret=connect(sc,(const struct sockaddr *)&addr,sizeof(addr));

	printf("connet:%d ",ret);

	FD_ZERO(&r);
	FD_SET(sc, &r);

	time.tv_sec=1;
	time.tv_usec=0;

	ret = select(sc, 0, &r, 0, &time);

	printf("start check ip %x port:%d ret=%d\n",ip,prot,ret);

	if(ret>0)
	{
		getsockopt(sc, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
		ret = (error==0)?1:0;
	}

CleanUp:
	close(sc);
	return ret;
}

void * thdfun(void * pParam)
{
	u_long ip;
	unsigned short prot;
	while(getip(ip,prot))
	{
		if(checkipprot(ip,prot,gtimeout)>0)
		{
			saveip(ip,prot);
		}
	}
}

int main(int argc,char* argv[])
{
	//得到命令行参数个数
	//gCmdline = CommandLineToArgv();
	//int argc = GetArgc();


	//初始化全局变量
	int nthd =100;
	gtimeout = 2000;
	gipend = 0;

	char *spath=NULL;
	//ghf = (HFILE)INVALID_HANDLE_VALUE;

	if(argc<2)
	{
useage:
		printf("Useage:\nmmscan.exe -a ((IP Host)|(IP begin)-(IP end)) -p (prot:80,33,44|135-1433) -T (thread:100) -t (timeout:2000 millisecond) -s (save result file:res.txt)\n");
		printf("For example:\r\n**.exe -a 192.168.0.0-192.169.0.0 -p 135 -T 250 -s c:\\result.txt \r\n\r\n");
		printf("**.exe -a 127.0.0.1 -p 1-65535 -T 100 -t 1000\r\n\r\n");
		printf("**.exe -a 172.0.0.0-173.0.0.0 -p 135,445,80,139 -T 250 -t 2000 -s res.txt\r\n\r\n");
		return 0;
	}

	int cc = 0;
	char *stmp,*stmp2;
	while(cc<argc-1)
	{
		cc++;
		stmp = argv[cc];
		if(stmp[0]!='-')
		{
			continue;
		}

		printf(" %c ",stmp[1]);
		switch(stmp[1])
		{
		case 'a':
				cc++;
				if(cc+1>argc)
					goto useage;
				stmp = argv[cc];
				stmp2=stmp;
				while(*stmp++!='-'&&*stmp!='\0'){}

				if(*stmp)
				{
					*(stmp-1)='\0';
					gipbeg = inet_addr(stmp2);
					gipend = inet_addr(stmp);
				}
				else
				{
					gipbeg = inet_addr(argv[cc]);
					gipend = gipbeg;
				}

				gipbeg = htonl(gipbeg);
				gipend = htonl(gipend);

				if(gipbeg > gipend)
					goto useage;
				gipcur = gipbeg;
				
				printf("ip:%s ",argv[cc]);
				
				break;
		case 't':
				cc++;
				if(cc>argc-1)
					goto useage;

				gtimeout = myatoi(argv[cc]);

				if(gtimeout > 75000 || gtimeout < 50)
					gtimeout = 2000;
				
				printf("time:%s ",argv[cc]);

				break;
		case 'T':
				cc++;
				if(cc>argc-1)
					goto useage;
				nthd = myatoi(argv[cc]);

				if(nthd > 500 || nthd < 1)
					nthd = 100;
				
				printf("thread:%s ",argv[cc]);
				
				break;
		case 'p':
				cc++;
				if(cc>argc-1)
					goto useage;
				getprotfromcl(argv[cc]);
				
				printf("port:%s ",argv[cc]);
				break;
		case 's':
				cc++;
				if(cc>argc-1)
					goto useage;

				spath = argv[cc];

				break;
		default:
				goto useage;
				break;

		}

	}

	if(gipend == 0)
		goto useage;

	/*OFSTRUCT fbuf;
	ghf = OpenFile(spath,&fbuf,OF_WRITE|OF_CREATE);
	if((HANDLE)ghf==INVALID_HANDLE_VALUE)
		ghf = OpenFile("res.txt",&fbuf,OF_WRITE|OF_CREATE);
	if((HANDLE)ghf==INVALID_HANDLE_VALUE)
	{
		printf("error! \r\n");
		return 0;
	}*/
	
	
	pthread_mutex_init(&gcse,NULL);
	pthread_mutex_init(&gcseip,NULL);

	printf("Scaning!\r\n");


	u_long thdid;
	pthread_t phd[512];

	for(int i=0;i<nthd;i++)
	{
		//phd[i]=CreateThread(NULL,0,thdfun,0,0,&thdid);
		pthread_create(phd+i,0,thdfun,(void*)&thdid);
		//Sleep(50);
	}

	for(int j=0;j<nthd;j++)
	{
		;//WaitForSingleObject(phd[j],INFINITE);

	}

	pthread_mutex_destroy(&gcse);
	pthread_mutex_destroy(&gcseip);
	sleep(5);
	printf("Scan Over! \r\n");
	return 0;
}
