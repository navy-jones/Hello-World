class MocaSwmParserTlv
{
public:
	//msglen = len(T) + len(L) + len(V) + ...
	//用户调用后，msg指针会移到一下TLV的开头（调用者保证value的字节序）
	void MocaSwmEncodeTlv(char* pmsg, int Tag, int Len ,const void* Value, int msglen);
	void MocaSwmDecodeTlv(const char* pmsg,int Tag, char* Value, int msglen);
	int AddMsgLen(int datalen);
};
