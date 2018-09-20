#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h> 

#define send_MAXSIZE 	50
#define recv_MAXSIZE 	256
#define NBNS_PORT 		137 		//NetBios-ns端口
#define ONE_SCAN_IPNUM  50

struct Q_NETBIOSNS	//Netbios-ns 询问包的结构
{
	unsigned short int tid;		//unsigned short int 占2字节
	unsigned short int flags;		
    unsigned short int questions;	//=1,表示询问
    unsigned short int answerRRS;	//=1,表示回答
	unsigned short int authorityRRS;	
	unsigned short int additionalRRS;		
	unsigned char name[34];	//Queries部分
    unsigned short int type;
    unsigned short int classe;
};
unsigned   long   Invert_IP(unsigned   long   NormalIp);   	//把IP转换成能直接递增和递减的地址
int 	Scan_MAC(unsigned long FirstIP, int DELta);
int 	Check_IP(char   *str);
int 	d_num=0;

int main(int argc, char* argv[])
{	
	unsigned   long   FirstIP,SecondIP;    
	int    DELta =0;				//IP差值，即IP个数

	if(argc == 2 )	//用法和输出IP检测正确性
	{		
		if(Check_IP(argv[1]) == 0 )
		{ 
			printf("[%s] is not a valid IPaddress\n", argv[1]);
			return 0;
		}
		FirstIP = inet_addr(argv[1]);	//inet_addr()返回的地址是网络字节二进制格式，类型in_addr_t(无符号的整形)
		SecondIP = inet_addr(argv[1]);  //inet_addr函数把网络主机地址(如192.168.1.10)为网络字节序二进制值，如果参数char *cp无效，函数返回-1
	}
	else if( argc == 3 )
	{		
		if(Check_IP(argv[1]) == 0 || Check_IP(argv[2]) ==0 )
		{			
			if(Check_IP(argv[1]) == 0 )
				printf("[%s] is not a valid IPaddress\n", argv[1]);
			if(Check_IP(argv[2]) == 0 ) 
				printf("[%s] is not a valid IPaddress\n", argv[2]);
			return 0;
		}		
		FirstIP = inet_addr(argv[1]);		//任意的开始地址 // in_addr_t  inet_addr(const char *cp);
		SecondIP = inet_addr(argv[2]);		//任意的结束地址
	}
	else 
	{
		printf("Usage[1]: %s Start_IP End_IP",argv[0]);
		printf("\t\t//Start_IP must be smaller than End_IP//\n");
		printf("Usage[2]: %s One_IP\n",argv[0]);
		return 0;
	}

	//FirstIP= inet_addr("192.168.48.129");		//任意的开始地址
	//SecondIP= inet_addr("192.168.48.137");		//任意的结束地址
	
	//转换成能直接递增和递减的地址
       FirstIP = Invert_IP(FirstIP);  
       SecondIP = Invert_IP(SecondIP);   
	if( SecondIP < FirstIP)
	{
		printf("[%s] is smaller than [%s]\n", argv[1],argv[2]);
		return 0;
	}
	DELta = SecondIP - FirstIP +1;
	int i = 0;
	//每次群发20个不同IP#define ONE_SCAN_IPNUM 20
	//次数是商QUET_NUM，最后一次群发REMANIND_NUM次。
	int QUET_NUM=DELta/ONE_SCAN_IPNUM;
	int REMANIND_NUM= DELta%ONE_SCAN_IPNUM;
	printf(" Start to scan MAC (%d)IPs......\n",DELta+1);
	printf(" %-16s%-16s%-16s%-16s\n","IP Address","HOST Name","GROUP Name","MAC Address");
	for(i=0;i<QUET_NUM+1;i++)
	{		
		//printf("循环次数:%d\n",i);
		if(i==QUET_NUM)
			Scan_MAC(FirstIP,REMANIND_NUM);
		else
			Scan_MAC(FirstIP,ONE_SCAN_IPNUM);
		//sleep(1000);
	}
	if(QUET_NUM!=0)
		printf(" %-16s%-16s%-16s%-16s\n","The Others","N/A","N/A","N/A");
	return 1;
}

//Check_IP 返回1，则IP正确；返回0，IP错误
int Check_IP(char * str)
{	
	int dot_count =0;
	int num_count = 0;
	//printf("%s\n",str);
	while( (*str) != '\0' )
	{
		if((*str) != '.')
		{
			if( (*str) <= '9' && (*str) >='0')
			{
				num_count = num_count*10+(int)(*str)-'0';
				if( num_count <0 || num_count >255 )
					return 0;
			}
			else
				return 0;
			
		}
		else
		{
			if( num_count ==0 && dot_count ==0 )
				return 0;
			dot_count++;
			if( num_count <0 || num_count >255 )
				return 0;
			num_count =0;//reset num_count to 0
		}
		str++;
	}
	if( dot_count != 3)
		return 0;
	return 1;
}

//把网络字节格式IP转换成能直接递增和递减的长整型
//
unsigned   long   Invert_IP(unsigned   long   NormalIp)//把字节序颠倒
{
      unsigned  char b1,b2,b3,b4;  
      b1 =  NormalIp & 0x00FF;  
      b2 =  (NormalIp >> 8) & 0x00FF;  
      b3 =  (NormalIp >> 16) & 0x00FF;  
      b4 =  (NormalIp >> 24) & 0x00FF;  
      return   (b1 << 24) |(b2 << 16) |(b3 << 8) |b4;  
}

//scan 有问题，一次循环为什么只有一个结果输出
//
int Scan_MAC(unsigned long FirstIP, int NUM)
{
	unsigned long TempStartIP = FirstIP;
	int sockfd;	//socket
	char send_buff[send_MAXSIZE];
	char recv_buff[recv_MAXSIZE];
	memset(send_buff,0,sizeof(send_buff)); 
	memset(recv_buff,0,sizeof(recv_buff)); 

	//构造netbios-ns-udp询问包结构
	//char  sendbuff[]="\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01";

	if( (sockfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
	{
		//printf("socket error\n");
		return 0;
	}
	
	//用一个socket  循环发送netbios-ns包
	int k=0;
	for(k=0;k<NUM;k++)
	{
		struct Q_NETBIOSNS nbns;

		nbns.tid=0x0000+d_num;
		//printf("nbns.tid == %d \n",nbns.tid);
		nbns.flags=0x0000;
		nbns.questions=0x0100;
		nbns.answerRRS=0x0000;
		nbns.authorityRRS=0x0000;	
		nbns.additionalRRS=0x0000;
		nbns.name[0]=0x20;nbns.name[1]=0x43;	nbns.name[2]=0x4b;	
		int j=0;
		for(j=3;j<34;j++)
			nbns.name[j]=0x41;
		nbns.name[33]=0x00;	
    	nbns.type=0x2100;
    	nbns.classe=0x0100;
		//memset(send_buff,..,sizeof(send_buff));	把send_buff设置为udp包格式
		memcpy(send_buff,&nbns,sizeof(nbns)); 
		
		struct sockaddr_in toAddr; 
		bzero((char*)&toAddr,sizeof(toAddr));
		toAddr.sin_family = AF_INET;
		toAddr.sin_addr.s_addr =Invert_IP(FirstIP+d_num);
		toAddr.sin_port = htons(NBNS_PORT); 

		d_num++;

		int send_num =0;
		//printf("nbns.tid == %d IP == %s\n",nbns.tid,inet_ntoa(toAddr.sin_addr));	
		send_num = sendto(sockfd, send_buff, sizeof(send_buff), 0, (struct sockaddr *)&toAddr, sizeof(toAddr) );
		//if(send_num != sizeof(send_buff))	//sizeof(nbns)=50 ?	
		//{
			//printf("sendto() error\n");
			//close(sockfd);
			//return 0;		
		//}
	}

	while(1)
	{
		fd_set fdset;
		struct timeval timeout={1,0}; //select等待1秒，1秒轮询，要非阻塞就置0
		//         timeout.tv_sec = 1;
       	//         timeout.tv_usec = 0;
		FD_ZERO(&fdset); 			//每次循环都要清空集合，否则不能检测描述符变化
		FD_SET(sockfd,&fdset); 	//添加描述符
		int maxfdp = sockfd+1; 	//描述符最大值加1
		switch(select(maxfdp,&fdset,NULL,NULL,&timeout)) //select使用
		{
			case -1: 
				//printf("[select error!]\n");
				return 0;//select错误，退出程序
			case 0:		//等待超时
				//printf("Host Name: %-30s ","NA");
				//printf("MAC: NA  ");
				//printf(" [time out!]\n");
				return 0; //再次轮询
			default:
				//unsigned int recv_num = 0;
				//recv_num = 
				recvfrom(sockfd, recv_buff, sizeof(recv_buff), 0,  (struct sockaddr *)NULL, (int*)NULL);
				//if( recv_num < 80 )
				//{
					//printf("recvfrom() too small\n");
					//close(sockfd);
				//	break;			
				//}
				//printf("recvfrom() ok\n");
				unsigned short int temptid=0;
				memcpy(&temptid,recv_buff,2);
				//unsigned  char b1,b2;
				//b1=temptid & 0x00FF;
				//b2=(temptid>> 8) & 0x00FF;
				//temptid = (b1<<8)|b2;
				//printf("temptid == %d \n",temptid);
				unsigned long Temp_IP2 = TempStartIP;
				Temp_IP2+=temptid;
				struct sockaddr_in toAddr; 
				bzero((char*)&toAddr,sizeof(toAddr));
				toAddr.sin_family = AF_INET;
				toAddr.sin_addr.s_addr =Invert_IP(Temp_IP2);
				toAddr.sin_port = htons(NBNS_PORT); 
				//printf("  IP: %-18s",inet_ntoa(toAddr.sin_addr));
				printf(" %-16s",inet_ntoa(toAddr.sin_addr));
				unsigned short int NumberOfNames = 0;
				memcpy(&NumberOfNames,recv_buff+56,1);
				
				int i=0;
				int NUM=(NumberOfNames>2?2:NumberOfNames);
				//printf("Host Name: ");
				for(i=0;i<NUM;i++)//依次读取netbios name
				{	
					char NetbiosName[16] ={0}; 
					memcpy(NetbiosName,recv_buff+57+i*18,16);	//Segmentation fault
					printf("%-16s",NetbiosName);
					//if(i != NUM-1) 		
					//	printf("/");
				}	
				//printf("MAC: ");
				unsigned short int mac[6]={0};
				for(i=0;i<6;i++)
				{
					memcpy(&mac[i],recv_buff+57+NumberOfNames*18+i,1);
					printf("%02X",mac[i]);
					if(i!=5) 		
						printf(":");
				}
				printf("\n");
		}
		//return 0;
	}
	return 1;
}

