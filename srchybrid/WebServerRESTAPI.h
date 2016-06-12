#pragma once
#include "WebServer.h"

#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#ifdef DEBUG
#include "rapidjson/prettywriter.h"
#endif
#include "rapidjson/filereadstream.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/error/en.h"

namespace rapidjson
{
#ifdef UNICODE
  typedef StringBuffer StringBufferT;
#ifdef DEBUG
  typedef PrettyWriter<StringBufferT, UTF16<>> WriterT;
#else
  typedef Writer<StringBufferT, UTF16<>> WriterT;
#endif
#else
  typedef StringBuffer StringBufferT;
#ifdef DEBUG
  typedef PrettyWriter<StringBufferT> WriterT;
#else
  typedef Writer<StringBufferT> WriterT;
#endif
#endif
}

class WebServerRESTAPI
{
  // ���HTTP״̬���Ӧ��ʾ�ַ���
  static const char* _getStatusString(int status);
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
  // ��������ͷ
  void _ProcessHeader(char* pHeader, DWORD dwHeaderLen);
  // ���ؽ��
  void _Response(int status, LPCSTR szStdResponse, rapidjson::StringBufferT& data);
  void _Response(int status, LPCSTR szStdResponse, const void* data, DWORD dwDataLen);
#ifdef DEBUG
  // �����ú���,�����������������ݽ�����ԭ������
  bool _Dump();
#endif // DEBUG

  bool _GetServerList();
  bool _GetClientList();
  bool _GetSharedList();
  bool _GetknownfList();
  bool _Action(CMapStringToString & list, CString action = NULL);


public:
  WebServerRESTAPI(CWebSocket* socket);
  ~WebServerRESTAPI();

  bool Process(char* pHeader, DWORD dwHeaderLen, char* pData, DWORD dwDataLen, in_addr inad);
  
};

