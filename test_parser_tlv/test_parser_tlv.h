class MocaSwmParserTlv
{
public:
	//msglen = len(T) + len(L) + len(V) + ...
	//�û����ú�msgָ����Ƶ�һ��TLV�Ŀ�ͷ�������߱�֤value���ֽ���
	void MocaSwmEncodeTlv(char* pmsg, int Tag, int Len ,const void* Value, int msglen);
	void MocaSwmDecodeTlv(const char* pmsg,int Tag, char* Value, int msglen);
	int AddMsgLen(int datalen);
};
