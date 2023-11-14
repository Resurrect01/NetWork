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
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
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
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};
//帧头部（以太网帧头）、硬件类型、协议类型、硬件地址长度、协议地址长度、操作类型、发送方硬件地址、发送方IP地址、接收方硬件地址和接收方IP地址。
struct ARPFrame_t               //ARP帧
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
#pragma pack()        //恢复缺省对齐方式
void getmask(pcap_if_t* ptr, pcap_addr_t* a, char errbuf[], pcap_if_t* alldevs)
{
	int index = 0;
	DWORD SendIP;
	DWORD RevIP;
	char PCAP_SRC_IF_STRING_CONS[9] = "rpcap://";
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING_CONS, NULL, &alldevs, errbuf) == -1)
	{
		cout << "获取网络接口时发生错误:" << errbuf << endl;
		return ;
	}
	//显示接口列表
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "网卡" << index + 1 << "\t" << ptr->name << endl;
		cout << "描述信息：" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}
}
int main()
{
	pcap_if_t* alldevs;//指向设备列表首部的指针
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
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
		cout << "网卡" << index + 1 << "\t" << ptr->name << endl;
		cout << "描述信息：" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}

	int num;
	cout << "请选要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_handle == NULL)
	{
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "成功打开该网卡"<< endl;
	}




	//确保NPcap只捕获以太网帧类型为ARP的数据包
	u_int netmask;
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;
	//这里使用了ptr指向的网络接口信息结构体中的子网掩码信息。通过((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr，将子网掩码的地址信息提取出来。
	bpf_program fcode;
	char packet_filter[] = "ether proto \\arp";
	//用于指定只捕获ARP包的条件
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0)
	{
		//pcap_compile函数用于编译过滤器规则，如果编译失败（返回值小于0），则输出错误信息，释放资源，然后程序退出。
		pcap_freealldevs(alldevs);
		return 0;
	}
	//设置过滤器
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		pcap_freealldevs(alldevs);
		return 0;
	}

	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//设置为本机广播地址255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//设置为虚拟的MAC地址66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//设置为0
		ARPFrame.SendHa[i] = 0x66;	
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址 112.112.112.112.112.112

	//将所选择的网卡的IP设置为请求的IP地址
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
		cout << "ARP请求发送成功" << endl;
		while (true)
		{
			int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (rtn == -1)
			{
				cout << "  捕获数据包时发生错误：" << errbuf << endl;
				return 0;
			}
			else
			{
				if (rtn == 0)
				{
					cout << "  没有捕获到数据报" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是不是一开始发的包
					{
						
						cout << " 捕获到回复的数据报,请求IP与其MAC地址对应关系如下：" << endl;
						printIP(IPPacket->SendIP);
						cout << "	-----	";
						printMAC(IPPacket->SendHa);
						cout << endl;
						break;
					}
				}
			}
		}
	//向网络发送数据包
	cout << "\n" << endl;
	cout << "向网络发送一个数据包" << endl;
	cout << "请输入请求的IP地址:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//将本机IP赋值给数据报的源IP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
	}
	else
	{
		cout << "ARP请求发送成功" << endl;
		
		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				cout << "  捕获数据包时发生错误：" << errbuf << endl;
				return 0;
			}
			else
			{
				if (n == 0)
				{
					cout << "  没有捕获到数据报" << endl;
				}
				else
				{
					IPPacket = (ARPFrame_t*)pkt_data;
					if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
					{
						cout << "  捕获到回复的数据报,请求IP与其MAC地址对应关系如下：" << endl;
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