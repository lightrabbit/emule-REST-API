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
#include "rapidjson/filereadstream.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/error/en.h"

using namespace rapidjson;

#ifdef UNICODE
typedef GenericStringBuffer<UTF16<>> StringBufferT;
typedef Writer<StringBufferT, UTF16<>, UTF16<>> WriterT;
#else
typedef GenericStringBuffer<UTF8<>> StringBufferT;
typedef Writer<StringBufferT, UTF8<>, UTF8<>> WriterT;
#endif

static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json\r\n");

static void WriteObject(WriterT& writer, CServer* server) 
{
  writer.StartObject();
  writer.Key(_T("name")); writer.String(server->GetListName());
  writer.Key(_T("ip")); writer.String(server->GetAddress());
  writer.Key(_T("port")); writer.Uint((unsigned int)server->GetPort());
  writer.Key(_T("description")); writer.String(server->GetDescription());
  //TODO: ���кü�������û�ӽ���
  writer.EndObject();
}

CString WebServerRESTAPI::_GetServerList(ThreadData Data, CString& param)
{
  CWebServer *pThis = (CWebServer *)Data.pThis;
  if (pThis == NULL)
    return _T("null");
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

WebServerRESTAPI::WebServerRESTAPI()
{

}


WebServerRESTAPI::~WebServerRESTAPI()
{
}

void WebServerRESTAPI::Process(ThreadData Data)
{
  CWebSocket *pSocket = Data.pSocket;
  int iStart = 6;
  CString sService = Data.sURL.Tokenize(_T("/"), iStart);
  CString sParam = Data.sURL.Mid(iStart);
  //TODO: ���������ӹ����ļ�,�����ļ�,�ϴ�����,���ض��еȴ���,��if...else if...else����ʽ
  if (sService == _T("server")) {
    pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
  } else {
    pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
  }
}
