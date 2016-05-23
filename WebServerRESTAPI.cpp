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
//������Ҫ����emule�İ汾������������һ���ṩ����ϵͳ�ȵ���Ϣ�� By ����
static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json\r\n");

static void WriteObject(WriterT& writer, CServer* server) 
{
  writer.StartObject();
  writer.Key(_T("listName")); writer.String(server->GetListName());//name��Ϊlistname
  writer.Key(_T("address")); writer.String(server->GetAddress());//ip��Ϊaddress By ����
  writer.Key(_T("port")); writer.Uint(server->GetPort());
  writer.Key(_T("description")); writer.String(server->GetDescription());
  //TODO: ����ʮ��������û�ӽ���

  //Notice:����������������д���벻Ҫ��������һ���ַ�
  //����CServer�ṩ�����Ծ������ @ 2016-5-24 01��03
  //�ƺ��в����������ظ��ģ�����ȥ����������ֶ�����IP���ԣ�

  //����Server.h�����CServer���ṩ�ĺ�����д
  //��дע�͵�ʱ�򣬺�Ȼ�뵽����������ƺ���ֹ����Server��Ϣ���Ͼ��ǡ�д���󡱣�
  //����Ҫ��ϸ�������κ�����Ҫʵ�ֵĹ���	@ 2016-5-23 23��10
  //ע�⵽������CServer�ģ��Ҿ�����ʼд
  //�Ҳ���֪��ÿһ�������ĺ��壬��˽�ֱ��ʹ�úͺ���һ�µ�����
  //��������GetXXXX->XXXX��ת��ΪȫСд	@23��21
  //��ע�⵽��Щ�����ƺ����ظ�������getip��getaddress
  //��������getfullip��getdynip�ȣ�ʹ��Сд��ֹ����������
  //���Ծ�����ÿ����д��ȥ����Ϊ�����ظ������������ӵ�����	@23��33
  //Server.h�ж���ķ����У���Щ���Ͳ���writer֧�֣���uint16��
  //����ʽ����ת����writer֧�ֵ�����
  //int����Ϊ��int32 @ 23��47
  //��ʽ����ת��ʱ��������������ʽ����ת��
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
  writer.Key(_T("uDPFlags")); writer.Uint(server->GetUDPFlags());//�о�����������ʲô���� By ����
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
  //�޸��˲��ֲ���������key����ʹ�����һ��
  //ͬʱ��Ҳ������eMule�Ĵ�������οӵ���@ 2016-5-24 01��03

  //����

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
