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
  // 获得HTTP状态码对应提示字符串
  static const char* _getStatusString(int status);
private:
  // 对应的Socket
  CWebSocket *Socket;
  // 请求的方法
  CString Method;
  // 请求的URL
  CString URL;
  // 未解析的查询字符串
  CString RawQueryString;
  // 未解析的路径
  CString RawPath;
  // 请求的路径, 从URL处理得来
  // 比如URL是:/aaa/bbb/ccc
  // 那么:
  // Path[0] = "aaa"
  // Path[1] = "bbb"
  // Path[2] = "ccc"
  CStringArray Path;
  // 请求的头部
  CMapStringToString Headers;
  // 查询字符串, 即对URL里面"?"符号后的aaa=bbb&ccc=ddd进行处理
  CMapStringToString QueryString;
  // 请求的数据
  char* Data;
  // 请求附带数据的长度
  DWORD DataLen;

private:
  // 处理请求头
  void _ProcessHeader(char* pHeader, DWORD dwHeaderLen);
  // 返回结果
  void _Response(int status, LPCSTR szStdResponse, rapidjson::StringBufferT& data);
  void _Response(int status, LPCSTR szStdResponse, const void* data, DWORD dwDataLen);
#ifdef DEBUG
  // 调试用函数,将请求所包含的内容解析后原样返回
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

