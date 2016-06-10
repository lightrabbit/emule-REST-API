#pragma once
#include "WebServer.h"
class WebServerRESTAPI
{
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

