#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "remote-ext.h"
#include "stdio.h"
#include<time.h>
#include <string>
#include<cstring>
#include<vector>
#include<set>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
void printMAC(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if(i<5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}
	
};
void printIP(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p;
};
#pragma pack(1)
struct FrameHeader_t //֡�ײ�
{
	BYTE DesMAC[6];  //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];  //Դ��ַ
	WORD FrameType;  //֡����
};
//֡ͷ������̫��֡ͷ����Ӳ�����͡�Э�����͡�Ӳ����ַ���ȡ�Э���ַ���ȡ��������͡����ͷ�Ӳ����ַ�����ͷ�IP��ַ�����շ�Ӳ����ַ�ͽ��շ�IP��ַ��
struct ARPFrame_t               //ARP֡
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()        //�ָ�ȱʡ���뷽ʽ
void getmask(pcap_if_t* ptr, pcap_addr_t* a, char errbuf[], pcap_if_t* alldevs)
{
	int index = 0;
	DWORD SendIP;
	DWORD RevIP;
	char PCAP_SRC_IF_STRING_CONS[9] = "rpcap://";
	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING_CONS, NULL, &alldevs, errbuf) == -1)
	{
		cout << "��ȡ����ӿ�ʱ��������:" << errbuf << endl;
		return ;
	}
	//��ʾ�ӿ��б�
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "����" << index + 1 << "\t" << ptr->name << endl;
		cout << "������Ϣ��" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}
}
int main()
{
	pcap_if_t* alldevs;//ָ���豸�б��ײ���ָ��
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	DWORD SendIP;
	DWORD RevIP;
	int index = 0;
	char PCAP_SRC_IF_STRING_CONS[9] = "rpcap://";

	void getmask(pcap_if_t * ptr, pcap_addr_t * a, char errbuf[], pcap_if_t * alldevs);
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING_CONS, NULL, &alldevs, errbuf);
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "����" << index + 1 << "\t" << ptr->name << endl;
		cout << "������Ϣ��" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}

	int num;
	cout << "��ѡҪ�򿪵������ţ�";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//������
	if (pcap_handle == NULL)
	{
		cout << "������ʱ��������" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "�ɹ��򿪸�����"<< endl;
	}




	//ȷ��NPcapֻ������̫��֡����ΪARP�����ݰ�
	u_int netmask;
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;
	//����ʹ����ptrָ�������ӿ���Ϣ�ṹ���е�����������Ϣ��ͨ��((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr������������ĵ�ַ��Ϣ��ȡ������
	bpf_program fcode;
	char packet_filter[] = "ether proto \\arp";
	//����ָ��ֻ����ARP��������
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0)
	{
		//pcap_compile�������ڱ�������������������ʧ�ܣ�����ֵС��0���������������Ϣ���ͷ���Դ��Ȼ������˳���
		pcap_freealldevs(alldevs);
		return 0;
	}
	//���ù�����
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		pcap_freealldevs(alldevs);
		return 0;
	}

	//��װ����
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//����Ϊ�����㲥��ַ255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//����Ϊ�����MAC��ַ66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//����Ϊ0
		ARPFrame.SendHa[i] = 0x66;	
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4; // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//ԴIP��ַ����Ϊ�����IP��ַ 112.112.112.112.112.112

	//����ѡ���������IP����Ϊ�����IP��ַ
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
		cout << "ARP�����ͳɹ�" << endl;
		while (true)
		{
			int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (rtn == -1)
			{
				cout << "  �������ݰ�ʱ��������" << errbuf << endl;
				return 0;
			}
			else
			{
				if (rtn == 0)
				{
					cout << "  û�в������ݱ�" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//�ж��ǲ���һ��ʼ���İ�
					{
						
						cout << " ���񵽻ظ������ݱ�,����IP����MAC��ַ��Ӧ��ϵ���£�" << endl;
						printIP(IPPacket->SendIP);
						cout << "	-----	";
						printMAC(IPPacket->SendHa);
						cout << endl;
						break;
					}
				}
			}
		}
	//�����緢�����ݰ�
	cout << "\n" << endl;
	cout << "�����緢��һ�����ݰ�" << endl;
	cout << "�����������IP��ַ:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//������IP��ֵ�����ݱ���ԴIP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP������ʧ��" << endl;
	}
	else
	{
		cout << "ARP�����ͳɹ�" << endl;
		
		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				cout << "  �������ݰ�ʱ��������" << errbuf << endl;
				return 0;
			}
			else
			{
				if (n == 0)
				{
					cout << "  û�в������ݱ�" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
					{
						cout << "  ���񵽻ظ������ݱ�,����IP����MAC��ַ��Ӧ��ϵ���£�" << endl;
						printIP(IPPacket->SendIP);
						cout << "	-----	";
						printMAC(IPPacket->SendHa);
						cout << endl;
						break;
					}
				}
			}
		}
	}

}