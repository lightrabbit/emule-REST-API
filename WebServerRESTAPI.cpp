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
//或许需要增加emule的版本？并像游览器一样提供操作系统等的信息？ By 柚子
static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json\r\n");

static void WriteObject(WriterT& writer, CServer* server) 
{
  writer.StartObject();
  writer.Key(_T("listName")); writer.String(server->GetListName());//name改为listname
  writer.Key(_T("address")); writer.String(server->GetAddress());//ip改为address By 柚子
  writer.Key(_T("port")); writer.Uint(server->GetPort());
  writer.Key(_T("description")); writer.String(server->GetDescription());
  //TODO: 还有十几个属性没加进来

  //Notice:以下是新手柚子锁写，请不要相信哪怕一个字符
  //所有CServer提供的属性均已添加 @ 2016-5-24 01：03
  //似乎有部分属性是重复的，可以去掉（例如多种多样的IP属性）

  //根据Server.h定义的CServer类提供的函数编写
  //在写注释的时候，忽然想到，这个函数似乎不止返回Server信息（毕竟是“写对象”）
  //我需要仔细看看整段函数所要实现的功能	@ 2016-5-23 23：10
  //注意到参数是CServer的，我决定开始写
  //我并不知道每一个参数的含义，因此将直接使用和函数一致的名字
  //命名规则：GetXXXX->XXXX并转换为全小写	@23：21
  //我注意到有些方法似乎有重复，例如getip和getaddress
  //甚至还有getfullip，getdynip等（使用小写防止被搜索到）
  //所以决定先每个都写上去，因为命名重复，先修正兔子的命名	@23：33
  //Server.h中定义的方法中，有些类型不被writer支持（如uint16）
  //将显式类型转换至writer支持的类型
  //int被认为是int32 @ 23：47
  //显式类型转换时，报错，将采用隐式类型转换
  writer.Key(_T("IP"));	writer.Uint(server->GetIP());

  writer.Key(_T("dynIP")); writer.String(server->GetDynIP());
  writer.Key(_T("fullIP")); writer.String(server->GetFullIP());
  writer.Key(_T("port")); writer.Uint((uint32)(server->GetPort()));
  writer.Key(_T("files")); writer.Uint(server->GetFiles());
  writer.Key(_T("users")); writer.Uint(server->GetUsers());
  writer.Key(_T("preference")); writer.Uint(server->GetIP());
  writer.Key(_T("ping")); writer.Uint(server->GetPing());
  writer.Key(_T("maxUsers")); writer.Uint(server->GetMaxUsers());
  writer.Key(_T("failedCount")); writer.Uint(server->GetFailedCount());
  writer.Key(_T("maxUsers")); writer.Uint(server->GetMaxUsers());
  writer.Key(_T("failedCount")); writer.Uint(server->GetFailedCount());
  writer.Key(_T("lastPingedTime")); writer.Uint(server->GetLastPingedTime());
  writer.Key(_T("realLastPingedTime")); writer.Uint(server->GetRealLastPingedTime());
  writer.Key(_T("gastPinged")); writer.Uint(server->GetLastPinged());
  writer.Key(_T("lastDescPingedCount")); writer.Uint(server->GetLastDescPingedCount());
  writer.Key(_T("isStaticMember")); writer.Bool(server->IsStaticMember());
  writer.Key(_T("challenge")); writer.Uint(server->GetChallenge());
  writer.Key(_T("descReqChallenge")); writer.Uint(server->GetDescReqChallenge());
  writer.Key(_T("softFiles")); writer.Uint(server->GetSoftFiles());
  writer.Key(_T("hardFiles")); writer.Uint(server->GetHardFiles());
  writer.Key(_T("version")); writer.String(server->GetVersion());
  writer.Key(_T("tCPFlags")); writer.Uint(server->GetTCPFlags());
  writer.Key(_T("uDPFlags")); writer.Uint(server->GetUDPFlags());//感觉这里命名有什么不对 By 柚子
  writer.Key(_T("lowIDUsers")); writer.Uint(server->GetLowIDUsers());
  writer.Key(_T("obfuscationPortTCP")); writer.Uint(server->GetObfuscationPortTCP());
  writer.Key(_T("obfuscationPortUDP")); writer.Uint(server->GetObfuscationPortUDP());
  writer.Key(_T("serverKeyUDP")); writer.Uint(server->GetServerKeyUDP());
  writer.Key(_T("isCryptPingReplyPending")); writer.Bool(server->GetCryptPingReplyPending());
  writer.Key(_T("serverKeyUDPIP")); writer.Uint(server->GetServerKeyUDPIP());
  writer.Key(_T("isSupportsUnicode")); writer.Bool(server->GetUnicodeSupport());
  writer.Key(_T("isSupportsRelatedSearch")); writer.Bool(server->GetRelatedSearchSupport());
  writer.Key(_T("isSupportsLargeFilesTCP")); writer.Bool(server->SupportsLargeFilesTCP());
  writer.Key(_T("isSupportsLargeFilesUDP")); writer.Bool(server->SupportsLargeFilesUDP());
  writer.Key(_T("isSupportsObfuscationUDP")); writer.Bool(server->SupportsObfuscationUDP());
  writer.Key(_T("isSupportsObfuscationTCP")); writer.Bool(server->SupportsObfuscationTCP());
  writer.Key(_T("isSupportsGetSourcesObfuscation")); writer.Bool(server->SupportsGetSourcesObfuscation());
  //修改了部分布尔变量的key名，使其更加一致
  //同时我也看出来eMule的代码是如何坑爹的@ 2016-5-24 01：03

  //以上

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
  //TODO: 在这里增加共享文件,下载文件,上传队列,下载队列等处理,用if...else if...else的形式
  if (sService == _T("server")) {
    pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
  } else {
    pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
  }
}
