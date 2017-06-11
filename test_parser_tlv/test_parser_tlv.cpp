#include <stdio.h>  
#include <WinSock2.h>  //windows
#include <string>  
#include "test_parser_tlv.h"
#include <iostream>
//#include <arpa/inet.h> //linux
  
#pragma comment(lib, "WS2_32")  
using namespace std;

enum emTLVNodeType  
{  
    emTlvNNone = 0,  
    emTlvNRoot,         //根节点  
    emTlvName,          //名字  
    emTlvAge,           //年龄  
    emTlvColor          //颜色 1 白色 2 黑色  
};  
  
enum emTlvTag
{
	SwmUpgradeProgress = 1,
	SwmUpgradeVer,      
	SwmUpgradeMode,   

};
enum emSwmUpgradeMode
{
	FastUpgrade = 1,
	NormalUpgrade,      
};
  
typedef struct _CAT_INFO  
{  
    char szName[12];  
    int iAge;  
    int iColor;  
}CAT_INFO,*LPCAT_INFO;  
  
class CTlvPacket  
{  
public:  
    CTlvPacket(char *pBuf,unsigned int len):m_pData(pBuf),m_uiLength(len),m_pEndData(m_pData+len),m_pWritePtr(m_pData),m_pReadPtr(m_pData) { }  
    ~CTlvPacket() { }  
  
    bool WriteInt(int data,bool bMovePtr = true)  
    {  
		cout<<"m_uilength"<<m_uiLength<<endl;
        int tmp = htonl(data);  
        return Write(&tmp,sizeof(int));  
    }  
  
    bool Write(const void *pDst,unsigned int uiCount)  
    {  
        ::memcpy(m_pWritePtr,pDst,uiCount);  
        m_pWritePtr += uiCount;  
        return m_pWritePtr < m_pEndData ? true : false;  
    }  
  
    bool ReadInt(int *data,bool bMovePtr = true)  
    {  
        Read(data,sizeof(int));  
        *data = ntohl(*data);  
        return true;  
    }  
  
    bool Read(void *pDst,unsigned int uiCount)  
    {  
        ::memcpy(pDst,m_pReadPtr,uiCount);  
        m_pReadPtr += uiCount;  
        return m_pReadPtr < m_pEndData ? true : false;  
    }  
  
private:  
    char *m_pData;  
    unsigned int m_uiLength;  
    char *m_pEndData;  
    char *m_pWritePtr;  
    char *m_pReadPtr;  
};  
  
/* 
 
格式： 
    Tag(root) L1 V 
                 T L V T L V T L V 
 
    L1 的长度即为“T L V T L V T L V”的长度 
 
*/  
  
int TLV_EncodeCat(LPCAT_INFO pCatInfo, char *pBuf, int &iLen)  
{  
    if (!pCatInfo || !pBuf)  
    {  
        return -1;  
    }  
	cout<<iLen<<endl;
    CTlvPacket enc(pBuf,iLen);  
    enc.WriteInt(emTlvNRoot);  
    enc.WriteInt(20+12+12); //根节点emTlvNRoot中的L，20=4+4+12，12=4+4+4，12=4+4+4  
  
    enc.WriteInt(emTlvName);  
    enc.WriteInt(12);  
    enc.Write(pCatInfo->szName,12);  
  
    enc.WriteInt(emTlvAge);  
    enc.WriteInt(4);  
    enc.WriteInt(pCatInfo->iAge);  
  
    enc.WriteInt(emTlvColor);  
    enc.WriteInt(4);  
    enc.WriteInt(pCatInfo->iColor);  
  
    iLen = 8+20+12+12; //总长度再加上emTLVNRoot的T和L，8=4+4  
	cout<<iLen<<endl;
  
    return 0;  
}  
  
int TLV_DecodeCat(char *pBuf, int iLen, LPCAT_INFO pCatInfo)  
{  
    if (!pCatInfo || !pBuf)  
    {  
        return -1;  
    }  
  
    CTlvPacket encDec(pBuf,iLen);  
    int iType;  
    int iSum,iLength;  
  
    encDec.ReadInt(&iType);  
    if (emTlvNRoot != iType)  
    {  
        return -2;  
    }  
    encDec.ReadInt(&iSum);  
  
    while (iSum > 0)  
    {  
        encDec.ReadInt(&iType);  
        encDec.ReadInt(&iLength);  
        switch(iType)  
        {  
        case emTlvName:  
            encDec.Read(pCatInfo->szName,12);  
            iSum -= 20;  
            break;  
        case emTlvAge:  
            encDec.ReadInt(&pCatInfo->iAge);  
            iSum -= 12;  
            break;  
        case emTlvColor:  
            encDec.ReadInt(&pCatInfo->iColor);  
            iSum -= 12;  
            break;  
        default:  
            printf("TLV_DecodeCat unkonwn error. \n");  
            break;  
        }  
    }  
  
    return 0;  
}  



void MocaSwmParserTlv::MocaSwmEncodeTlv(char* pmsg, int Tag, int Len ,const void* Value, int msglen)
{
	Tag = htonl(Tag);
	memcpy_s(pmsg, msglen, &Tag, sizeof(int));
	pmsg += sizeof(int);

	int Len_tmp = htonl(Len);
	memcpy_s(pmsg, msglen, &Len_tmp, sizeof(int));
	pmsg += sizeof(int);

	memcpy_s(pmsg, msglen, Value, Len);
	pmsg += Len;

	pmsg -= msglen;
}


void MocaSwmParserTlv::MocaSwmDecodeTlv(const char* pmsg, int Tag, char* Value, int msglen)
{
	int position = 0;
	int tag_tmp = 0xFFFFFFFF;
	int len_tmp = 0xFFFFFFFF;

	for (position; position < msglen; )
	{
		memcpy_s(&tag_tmp, sizeof(int), pmsg, sizeof(int));
		tag_tmp = ntohl(tag_tmp);
		position += sizeof(int);

		if (tag_tmp == Tag)
		{
			memcpy_s(&len_tmp, sizeof(int), pmsg+position, sizeof(int));
			len_tmp = ntohl(len_tmp);
			position += sizeof(int);

			memcpy_s(Value, len_tmp, pmsg+position, len_tmp);

			break;
		}
		else
		{
			memcpy_s(&len_tmp, sizeof(int), pmsg+position, sizeof(int));
			len_tmp = ntohl(len_tmp);
			position += sizeof(int);
			position += len_tmp;
		}
	}
	if (position >= msglen)
	{
	    cout<<"not found"<<endl;
	}
}
int MocaSwmParserTlv::AddMsgLen(int datelen)
{
	return (sizeof(int) + sizeof(int) + datelen);
}

int main(int argc, char* argv[])  
{  
  
    int iRet, iLen;  
    char buf[256] = {0};  
  
    CAT_INFO cat;  
    memset(&cat,0,sizeof(cat));  
    strcpy_s(cat.szName,sizeof(cat.szName),"Tom");  
    cat.iAge = 5;  
    cat.iColor = 2;  
  
    iRet = TLV_EncodeCat(&cat,buf,iLen);  
    if ( 0 == iRet )  
    {  
        printf("TLV_EncodeCat ok, iLen = %d. \n",iLen);  
    }  
    else  
    {  
        printf("TLV_EncodeCat error \n");  
    }  
  
    memset(&cat,0,sizeof(cat));  
    iRet = TLV_DecodeCat(buf,iLen,&cat);  
    if ( 0 == iRet )  
    {  
        printf("TLV_DecodeCat ok, cat name = %s, age = %d, color = %d. \n",cat.szName,cat.iAge,cat.iColor);  
    }  
    else  
    {  
        printf("TLV_DecodeCat error, code = %d. \n", iRet);  
    }  
  

	MocaSwmParserTlv my_oarsertlv = MocaSwmParserTlv();
	int total_msg_len = 0;
	int my_send_tag = SwmUpgradeMode;
	int my_send_value = FastUpgrade;
	int value_len = sizeof(my_send_value);
	total_msg_len += my_oarsertlv.AddMsgLen(sizeof(my_send_value));
	char* pmsg = (char *)malloc(total_msg_len);
	my_oarsertlv.MocaSwmEncodeTlv(pmsg, my_send_tag, value_len, (const void*)&my_send_value, total_msg_len);
	cout<<"send value"<<endl;

	memset(&my_send_value, 0, sizeof(4));
	my_oarsertlv.MocaSwmDecodeTlv((char const*)pmsg, my_send_tag, (char*)&my_send_value, 12);

	free(pmsg);pmsg=NULL;
    int iWait = getchar();  
    return 0;  
} 