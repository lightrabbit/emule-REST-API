#include "stdafx.h"
#include <locale.h>
#include "emule.h"
#include "StringConversion.h"
#include "WebServer.h"
#include "ClientCredits.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "ED2KLink.h"
#include "emuledlg.h"
#include "FriendList.h"
#include "MD5Sum.h"
#include "ini2.h"
#include "Kademlia/Kademlia/Kademlia.h"
#include "KademliaWnd.h"
#include "KadSearchListCtrl.h"
#include "kademlia/kademlia/Entry.h"
#include "KnownFileList.h"
#include "ListenSocket.h"
#include "Log.h"
#include "MenuCmds.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "Server.h"
#include "ServerList.h"
#include "ServerWnd.h"
#include "SearchList.h"
#include "SearchDlg.h"
#include "SearchParams.h"
#include "SharedFileList.h"
#include "Sockets.h"
#include "StatisticsDlg.h"
#include "Opcodes.h"
#include "QArray.h"
#include "TransferDlg.h"
#include "UploadQueue.h"
#include "UpDownClient.h"
#include "UserMsgs.h"

#include "WebServerRESTAPI.h"

#include <iostream>
#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#ifdef DEBUG
#include "rapidjson/prettywriter.h"
#endif
#include "rapidjson/filereadstream.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/error/en.h"

using namespace rapidjson;

#ifdef UNICODE
typedef GenericStringBuffer<UTF16<>> StringBufferT;
#ifdef DEBUG
typedef PrettyWriter<StringBufferT, UTF16<>, UTF16<>> WriterT;
#else
typedef Writer<StringBufferT, UTF16<>, UTF16<>> WriterT;
#endif
#else
typedef GenericStringBuffer<UTF8<>> StringBufferT;
#ifdef DEBUG
typedef PrettyWriter<StringBufferT, UTF8<>, UTF8<>> WriterT;
#else
typedef Writer<StringBufferT, UTF8<>, UTF8<>> WriterT;
#endif
#endif

static const TCHAR* JSONInit = _T("Server: eMule REST API\r\nConnection: close\r\nContent-Type: application/json\r\n");

static void WriteObject(WriterT& writer, CServer* server) 
{
  writer.StartObject();
  writer.Key(_T("name")); writer.String(server->GetListName());
  writer.Key(_T("ip")); writer.String(server->GetAddress());
  writer.Key(_T("port")); writer.Uint((unsigned int)server->GetPort());
  writer.Key(_T("description")); writer.String(server->GetDescription());
  //TODO: 还有好几个属性没加进来
  writer.EndObject();
}

void WebServerRESTAPI::_ProcessHeader(char * pHeader, DWORD dwHeaderLen)
{
  CStringA header(pHeader, dwHeaderLen);
  //处理头部
  int tokenPos = 0;
  Method = header.Tokenize(" ", tokenPos);
  URL = header.Tokenize(" ", tokenPos);
  header.Tokenize("\n", tokenPos);

  while (tokenPos >= 0) {
    CString key(header.Tokenize(":", tokenPos));
    if (tokenPos < 0) break;
    CString value(header.Tokenize("\n", tokenPos).Trim());
    if (tokenPos < 0) break;
    Headers[key] = value;
  }

  //分离路径和查询字符串
  int queryPos = URL.FindOneOf(_T("?"));
  if (queryPos > 0) {
    RawPath = OptUtf8ToStr(URLDecode(URL.Left(queryPos)));
    RawQueryString = URL.Mid(queryPos + 1);
  } else {
    RawPath = URL;
  }
  
  //处理路径
  CString sToken;
  tokenPos = 1;
  while ((sToken = RawPath.Tokenize(_T("/?"), tokenPos)) != _T("")) {
    Path.Add(sToken);
  }

  //处理查询字符串
  tokenPos = 0;
  while (tokenPos >= 0) {
    CString key(RawQueryString.Tokenize(_T("="), tokenPos));
    if (tokenPos < 0) break;
    CString value(RawQueryString.Tokenize(_T("&"), tokenPos));
    if (tokenPos < 0) break;
    QueryString[key] = OptUtf8ToStr(URLDecode(value));
  }
}

CString WebServerRESTAPI::_GetServerList()
{
  StringBufferT s;
  WriterT writer(s);

  writer.StartArray();
  
  for (uint32 sc = 0; sc < theApp.serverlist->GetServerCount(); sc++)
  {
    CServer* cur = theApp.serverlist->GetServerAt(sc);
    WriteObject(writer, cur);
  }

  writer.EndArray();
  return s.GetString();
}
#ifdef DEBUG
CString WebServerRESTAPI::_Dump()
{
  StringBufferT s;

  WriterT writer(s);
  writer.StartObject();
    
    writer.Key(_T("Method"));  writer.String(Method);
    writer.Key(_T("URL"));  writer.String(URL);
    writer.Key(_T("RawQueryString"));  writer.String(RawQueryString);
    writer.Key(_T("RawPath"));  writer.String(RawPath);

    writer.Key(_T("Headers"));
    writer.StartObject();
    {
      POSITION i = Headers.GetStartPosition();
      while (i != NULL) {
        CString key;
        CString value;
        Headers.GetNextAssoc(i, key, value);
        writer.Key(key);  writer.String(value);
      }
    }
    writer.EndObject();

    writer.Key(_T("Path"));
    writer.StartArray();
    for (int i = 0; i < Path.GetCount(); i++)
      writer.String(Path[i]);
    writer.EndArray();

    writer.Key(_T("QueryString"));
    writer.StartObject();
    {
      POSITION i = QueryString.GetStartPosition();
      while (i != NULL) {
        CString key;
        CString value;
        QueryString.GetNextAssoc(i, key, value);
        writer.Key(key);  writer.String(value);
      }
    }
    writer.EndObject();

    writer.Key(_T("Data"));  writer.String(CString(CStringA(Data, DataLen)));
    writer.Key(_T("DataLen")); writer.Uint(DataLen);

  writer.EndObject();
  return s.GetString();
}
#endif
WebServerRESTAPI::WebServerRESTAPI(CWebSocket *socket)
{
  Socket = socket;
}


WebServerRESTAPI::~WebServerRESTAPI()
{
}

bool WebServerRESTAPI::Process(char* pHeader, DWORD dwHeaderLen, char* pData, DWORD dwDataLen, in_addr inad)
{
  _ProcessHeader(pHeader, dwHeaderLen);
  Data = pData;
  DataLen = dwDataLen;
  //TODO: 在这里增加共享文件,下载文件,上传队列,下载队列等处理,用if...else if...else的形式
  if (Path[0] == _T("server")) {
    Socket->SendContent(CT2CA(JSONInit), _GetServerList());
    return true;
  } else if (Path[0] == _T("dump")) {
#ifdef DEBUG
    Socket->SendContent(CT2CA(JSONInit), _Dump());
    return true;
#else
    return false;
#endif
  } else {
    return false;
  }
}
