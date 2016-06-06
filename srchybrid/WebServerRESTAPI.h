#pragma once
#include "WebServer.h"
class WebServerRESTAPI
{
private:
  // ��Ӧ��Socket
  CWebSocket *Socket;
  // ����ķ���
  CString Method;
  // �����URL
  CString URL;
  // δ�����Ĳ�ѯ�ַ���
  CString RawQueryString;
  // δ������·��
  CString RawPath;
  // �����·��, ��URL�������
  // ����URL��:/aaa/bbb/ccc
  // ��ô:
  // Path[0] = "aaa"
  // Path[1] = "bbb"
  // Path[2] = "ccc"
  CStringArray Path;
  // �����ͷ��
  CMapStringToString Headers;
  // ��ѯ�ַ���, ����URL����"?"���ź��aaa=bbb&ccc=ddd���д���
  CMapStringToString QueryString;
  // ���������
  char* Data;
  // ���󸽴����ݵĳ���
  DWORD DataLen;

private:
  void _ProcessHeader(char* pHeader, DWORD dwHeaderLen);
  CString _GetServerList();
#ifdef DEBUG
  // �����ú���,�����������������ݽ�����ԭ������
  CString _Dump();
#endif // DEBUG
  
  

public:
  WebServerRESTAPI(CWebSocket* socket);
  ~WebServerRESTAPI();

  bool Process(char* pHeader, DWORD dwHeaderLen, char* pData, DWORD dwDataLen, in_addr inad);
  
};

