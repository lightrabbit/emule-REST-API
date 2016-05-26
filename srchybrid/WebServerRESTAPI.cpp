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
#include "SafeFile.h"
#include "Kademlia/Utils/KadClientSearcher.h"
#include <io.h>
#include "Friend.h"
#include "emuledlg.h"
#include "FriendListCtrl.h"
#include "Packets.h"
#include "clientlist.h"


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
static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json; charset=UTF-8\r\n");
//WriteObject应该读取那些种类的数据？
static void WriteObject(WriterT& writer, CServer* server)
{
	writer.StartObject();
	writer.Key(_T("listName")); writer.String(server->GetListName());//name改为listname
	writer.Key(_T("address")); writer.String(server->GetAddress());//ip改为address By 柚子
	writer.Key(_T("port")); writer.Uint(server->GetPort());
	writer.Key(_T("description")); writer.String(server->GetDescription());
	//TODO: 还有十几个属性没加进来	--已添加 ，重复项已删除 By Yuzu
	//Notice:以下是新手柚子所写，请不要相信哪怕一个字符
	//根据Server.h定义的CServer类提供的函数编写
	//所有CServer提供的属性均已添加 @ 2016-5-24 01：03
	//似乎有部分属性是重复的，可以去掉（例如多种多样的IP属性）
	//将直接使用和函数一致的名字
	//命名规则：GetXXX->XXX;HasXXX->hasXXX;Bool的在前面补充is	@23：21
	writer.Key(_T("dynIP")); writer.String(server->GetDynIP());
	writer.Key(_T("IP"));	writer.Uint(server->GetIP());
	writer.Key(_T("dynIP")); writer.String(server->GetDynIP());
	writer.Key(_T("hasDynIP")); writer.Bool(server->HasDynIP());
	writer.Key(_T("fullIP")); writer.String(server->GetFullIP());
	writer.Key(_T("port")); writer.Uint(server->GetPort());
	writer.Key(_T("files")); writer.Uint(server->GetFiles());
	writer.Key(_T("users")); writer.Uint(server->GetUsers());
	writer.Key(_T("preference")); writer.Uint(server->GetPreference());
	writer.Key(_T("ping")); writer.Uint(server->GetPing());
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
	//对比CServer类检查了上面属性的完整性--已完成@ 2016-5-25 10：10
	//再次删除了重复项。
	writer.EndObject();
}

//我正在尝试写一个返回好友的函数，因为好友列表所需要返回的数据相对独立
//我忽然想到 WriteObiect的函数名或许有歧义，
//可能与前端操作对象（比如增加好友）的函数名重复？@ 2016-5-24 3：00
//CFriend类的风格与CServer类的风格有一定差异，需要注意一下。
CString ArrayToHex(const uchar* str, int len = 0)//总感觉我的理解错了@20：24
{                                              //不知为何，我总觉得会十分搞笑
	char T16[] = "0123456789ABCDEF", tmp[256], *ptr;
	ptr = tmp;
	if (len == 0) {
		while (*ptr++)len++;
		ptr = tmp;
	}
	if (len > 127)return _T("Too Large!");
	while (len--) {
		*ptr = T16[*str / 16]; ptr++;
		*ptr = T16[*str % 16]; ptr++;
		str++;
	}
	*ptr = '\0';
	return CString(tmp);
}
//TODO:完成CUpDownClient类型的返回
static void WriteObject(WriterT& writer, CUpDownClient* client, bool index = false)
{ //我注意到CUpDownClient类中有GetFriend()方法返回CFriend类 
  //CFriend类中有GetLinkedClient()方法返回CUpDownClient类
  //如何才能避免无限递归？
  //一个可行的方法是，所有WriteObject中调用的WriteObject方法，只返回索引信息，不返回详细信息


	if (index) {
		writer.Key(_T("clientUserHash")); writer.String(ArrayToHex(client->GetUserHash()));//uchar[16]
	}
	else {
		writer.StartObject();
		writer.Key(_T("Client")); writer.String(_T("NotSupportted"));
		writer.EndObject();
	}

}

static void WriteObject(WriterT& writer, CFriend* pail)//因为friend是关键字，这里用pail 
{
	CUpDownClient* Client;
	Client = pail->GetLinkedClient();

	writer.StartObject();
	writer.Key(_T("userHash")); writer.String(CString(pail->m_abyUserhash));//uchar[16]
	writer.Key(_T("lastSeen")); writer.Int64(pail->m_dwLastSeen);//有可能是64位时间
	writer.Key(_T("lastUsedIP")); writer.Int(pail->m_dwLastUsedIP);
	writer.Key(_T("lastUsedPort")); writer.Int(pail->m_nLastUsedPort);
	writer.Key(_T("lastChatted")); writer.Int(pail->m_dwLastChatted);
	writer.Key(_T("name")); writer.String(pail->m_strName);
	//TODO:讨论GetLinkedClient();的发送格式并实现	--准备进行
	WriteObject(writer, Client);
	//以及GetClientForChatSession();的功能及实现
	writer.Key(_T("isTryToConnet")); writer.Bool(pail->IsTryingToConnect());
	writer.Key(_T("isFriendSlotted")); writer.Bool(pail->GetFriendSlot());
	writer.Key(_T("hasUserHash")); writer.Bool(pail->HasUserhash());
	writer.Key(_T("hasKadID")); writer.Bool(pail->HasKadID());

	writer.EndObject();
}
//似乎返回CFriend是完全没有必要的？返回CUpDownClient类就好了
//里面也有isFriend方法，如果需要返回所有Friend，通过查询所有
//isFriend()=Ture的Client就好
//以上

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
	int iStart = 6;	//Magic number？？
	CString sService = Data.sURL.Tokenize(_T("/"), iStart);
	CString sParam = Data.sURL.Mid(iStart);
	//TODO: 在这里增加共享文件,下载文件,上传队列,下载队列等处理,用if...else if...else的形式
	if (sService == _T("server")) {
		pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
	}
	else if (sService == _T("friend")) {
		//pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
		//TODO: 读取friendlist
		;
	}
	else {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
	}
}
