// Must be run by root lol! Just datagram, no payload/data
// http://www.tenouk.com/Module43a.html
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
 
#define PCKT_LEN 8192
 
struct ipheader {
 unsigned char      iph_ihl:5, iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned char      iph_flag;
 unsigned short int iph_offset;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
};
 

struct udpheader {
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
};

in_addr_t ipOrigem;
in_addr_t ipDestino;
short int portaOrigem;
short int portaDestino;

 
// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{       //
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
}

void envia(int sd, char* msg){
    char buffer[PCKT_LEN];
    int one = 1;
    const int *val = &one;  
    memset(buffer, 0, PCKT_LEN);
    struct sockaddr_in sin, din;
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    char* texto = (char*) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    texto = msg;
    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = portaOrigem;
    din.sin_port = portaDestino;
    
    // IP addresses
    sin.sin_addr.s_addr = ipOrigem;
    din.sin_addr.s_addr = ipDestino;
         
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = 64;
    ip->iph_protocol = 17;
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = ipOrigem;
    // The destination IP address
    ip->iph_destip = ipDestino;
     
    udp->udph_srcport = portaOrigem;
    udp->udph_destport = portaDestino;
    udp->udph_len = htons(sizeof(struct udpheader));
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    else
        printf("setsockopt() is OK.\n");
     
    printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", ipOrigem, portaOrigem, ipDestino, portaDestino);
 
    if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }
    else
    {
        printf("sendto() is OK.\n");
    }
}

void recebe(int sd){
    unsigned char buffer[PCKT_LEN];
    
    if(recv(sd, (char*) &buffer, PCKT_LEN, 0) < 0){
        perror("recv");
        close(sd);
        exit(1);
    }

    char* msg = (char*) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    if(strcmp(msg, "porta 1") == 0){
        envia(sd, "Você encontrou uma sala com um computador. Você deseja acessar o computador, ou seguir em frente?\n (Digite 'acessar' ou 'seguir')");
    }
    if(strcmp(msg, "acessar") == 0){
        envia(sd, "Na tela do computador está escrito: 'O homem só envelhece quando os lamentos substituem seus sonhos'.\n(Digite 'sair' para sair do computador)");
    }
    if(strcmp(msg, "sair") == 0){
        envia(sd, "Você encontrou uma sala com um computador. Você deseja acessar o computador, ou seguir em frente?\n (Digite 'acessar' ou 'seguir')");
    }
    if(strcmp(msg, "seguir") == 0){
        envia(sd, "Você chegou na cozinha. Você pode comer um sanduíche, tomar um suco ou ir para a porta 3.\n(Digite 'comer', 'tomar' ou 'porta 3')");
    }
    if(strcmp(msg, "comer") == 0){
        envia(sd, "Você comeu um sanduíche natural! Você sabia que pessoas vegetarianas ou veganas costumam ter dificuldade de encontrar um lanche que atenda às suas necessidades e estilo de vida?\n(Digite 'levantar' para voltar à cozinha)");
    }
    if(strcmp(msg, "levantar") == 0){
        envia(sd, "Você está na cozinha. Você pode comer um sanduíche, tomar um suco ou ir para a porta 3.\n(Digite 'comer', 'tomar' ou 'porta 3')");
    }
    if(strcmp(msg, "tomar") == 0){
        envia(sd, "Você tomou um suco de limão! Você sabia que o suco de limão é ótimo para o cuidado com os dentes?\n(Digite 'levantar' para voltar à cozinha)");
    }
    if(strcmp(msg, "porta 3") == 0){
        envia(sd, "Você chegou ao final do jogo!");
    }
    if(strcmp(msg, "porta 2") == 0){
        envia(sd, "Você chegou na sala. Você pode assistir TV, ou ir para a cozinha.\n(Digite 'tv' ou 'cozinha')");    
    }
    if(strcmp(msg, "tv") == 0){
        envia(sd, "Você assistiu ao filme Star Wars. Que a força esteja com você! \n(Digite 'sala' para voltar à sala)");
    }
    if(strcmp(msg, "cozinha") == 0){
        envia(sd, "Você chegou na cozinha. Você pode comer um sanduíche, tomar um suco ou ir para a porta 3.\n(Digite 'comer', 'tomar' ou 'porta 3')");
    }
    if(strcmp(msg, "sala") == 0){
        envia(sd, "Você está na sala. Você pode assistir TV, ou ir para a cozinha.\n(Digite 'tv' ou 'cozinha')");    
    }
}


// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char *argv[])
{
    int sd;

     
    if(argc != 5)
    {
    printf("- Invalid parameters!!!\n");
    printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
    exit(-1);
    }
     
    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0)
    {
    perror("socket() error");
    // If something wrong just exit
    exit(-1);
    }
    else
    printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
    
    portaOrigem = htons(atoi(argv[2]));
    portaDestino = htons(atoi(argv[4]));
    ipOrigem = inet_addr(argv[1]);
    ipDestino = inet_addr(argv[3]);
    envia(sd, "Você está em uma casa desconhecida, à sua frente existem duas portas, a porta 1, e a porta 2. Em qual porta deseja entrar? \n(Digite 'porta 1' ou 'porta 2')");     
    recebe(sd);    

    close(sd);
    return 0;
}
