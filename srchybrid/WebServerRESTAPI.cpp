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
static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json; charset=UTF-8\r\n");
class JSONWriter :public WriterT {
public:
	JSONWriter(StringBufferT&os) :WriterT(os) {}
	
	//或许需要增加emule的版本？并像游览器一样提供操作系统等的信息？ By 柚子
	//Object应该读取那些种类的数据？
	void Object(CServer* server){
		StartObject();
		Key(_T("name")); String(server->GetListName());
		Key(_T("address")); String(server->GetAddress());
		Key(_T("port")); Uint(server->GetPort());
		Key(_T("description")); String(server->GetDescription());
		Key(_T("IP"));	Uint(server->GetIP());
		Key(_T("IPstr")); String(server->GetFullIP());
		Key(_T("files")); Uint(server->GetFiles());
		Key(_T("users")); Uint(server->GetUsers());
		Key(_T("preference")); Uint(server->GetPreference());
		Key(_T("ping")); Uint(server->GetPing());
		Key(_T("failedCount")); Uint(server->GetFailedCount());
		Key(_T("lastPinged")); Uint(server->GetLastPinged());
		Key(_T("lastDescPingedCount")); Uint(server->GetLastDescPingedCount());
		Key(_T("isStaticMember")); Bool(server->IsStaticMember());
		Key(_T("softFiles")); Uint(server->GetSoftFiles());
		Key(_T("hardFiles")); Uint(server->GetHardFiles());
		Key(_T("version")); String(server->GetVersion());
		Key(_T("lowIDUsers")); Uint(server->GetLowIDUsers());
		//删除了不必要的项目	by Yuzu @ 2016-6-1	15：45
		EndObject();
	}

	//我正在尝试写一个返回好友的函数，因为好友列表所需要返回的数据相对独立
	//我忽然想到 WriteObiect的函数名或许有歧义，
	//可能与前端操作对象（比如增加好友）的函数名重复？@ 2016-5-24 3：00
	//CFriend类的风格与CServer类的风格有一定差异，需要注意一下。
	void Object(CClientCredits* credit, unsigned char index = 0) {
		if (!index)StartObject();
		Key(_T("uploadedTotal")); Uint64(credit->GetUploadedTotal());
		Key(_T("downloadedTotal")); Uint64(credit->GetDownloadedTotal());
		if (!index)EndObject();
	}
	//TODO:完成CUpDownClient类型的返回
	//list=CClientList
	CString ArrToHex(const uchar* str, unsigned int len) {
		const char T16[] = "0123456789abcdef";
		char hex[4095];
		if (len != 0) {
			for (int i = 0; i < len; i++) {
				hex[i * 2] = T16[str[i] % 16];
				hex[i * 2 + 1] = T16[str[i] / 16];
			}
			hex[i * 2] = '\0';
			return CString(hex);
		}
		return CString("");
	}
	void Object(CUpDownClient* client, unsigned char index = 0)
	{ //我注意到CUpDownClient类中有GetFriend()方法返回CFriend类 
	  //CFriend类中有GetLinkedClient()方法返回CUpDownClient类
	  //如何才能避免无限递归？
	  //一个可行的方法是，所有Object中调用的Object方法，只返回索引信息，不返回详细信息

		StartObject();
		Key(_T("uploadDatarate")); Uint(client->GetUploadDatarate());
		Key(_T("userHash")); String(CString(ArrToHex(client->GetUserHash(),16)));
		Key(_T("hashType")); Int(client->GetHashType());
		Key(_T("isBanned")); Bool(client->IsBanned());
		Key(_T("userName")); String(CString(client->GetUserName()));
		Key(_T("SoftVer")); String(client->GetClientSoftVer());
		/*
			case SO_EMULE:			return _T("1");
			case SO_OLDEMULE:		return _T("1");
			case SO_EDONKEY:		return _T("0");
			case SO_EDONKEYHYBRID:	return _T("h");
			case SO_AMULE:			return _T("a");
			case SO_SHAREAZA:		return _T("s");
			case SO_MLDONKEY:		return _T("m");
			case SO_LPHANT:			return _T("l");
			case SO_URL:			return _T("u");
			*/
		Key(_T("IP")); Uint(client->GetIP());
		Key(_T("connectIP")); Uint(client->GetConnectIP());
		Key(_T("userPort")); Uint(client->GetUserPort());
		Key(_T("isFriend")); Bool(client->IsFriend());
		//Object(client->CheckAndGetReqUpFile());//CKnownFile
		Key(_T("transferredUp")); Uint(client->GetTransferredUp());
		Key(_T("transferredDown")); Uint(client->GetTransferredDown());
		Key(_T("clientVersion")); Int(client->GetClientSoft());
		Key(_T("clientModVer")); String(client->GetClientModVer());
		Key(_T("version")); Uint(client->GetVersion());
		Key(_T("muleVersion")); Uint(client->GetMuleVersion());
		if (client->Credits())
			Object(client->Credits(), index + 1);	
		else {
			Key(_T("credit")); String(_T("null"));
		}
		Key(_T("hasLowID")); Bool(client->HasLowID());
		Key(_T("isEd2kClient")); Bool(client->IsEd2kClient());
		//Object(client->GetFriend(),index+1);//警告：可能产生无穷递归
		EndObject();
	
	}
	void Object(CFriend* pail, unsigned char index = 0)//因为friend是关键字，这里用pail 
	{
		if (!index)StartObject();
		Key(_T("lastSeen")); Uint64(pail->m_dwLastSeen);//有可能是64位时间
		Key(_T("friendName")); String(pail->m_strName);
		//Key(_T("isFriendSlotted")); Bool(pail->GetFriendSlot());
		if (!index)EndObject();
	}
	//似乎返回CFriend是完全没有必要的？返回CUpDownClient类就好了
	//里面也有isFriend方法，如果需要返回所有Friend，通过查询所有
	//isFriend()=Ture的Client就好


	void Object(CAbstractFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Key(_T("fileName")); String(file->GetFileName());
		Key(_T("fileType")); String(file->GetFileType());
		Key(_T("fileTypeDisplayName")); String(file->GetFileTypeDisplayStr());
		Key(_T("hasNullHash")); Bool(file->HasNullHash());
		Key(_T("fileHash")); String(ArrToHex(file->GetFileHash(),16));
		Key(_T("eD2kLink")); String(file->GetED2kLink());//without Hashset;HTMLTag;HostName;Source;dwSourceIP
		Key(_T("fileSize")); String(CastItoXBytes(file->GetFileSize(), false, false));//TODO: Object for EMFileSize
		Key(_T("hasComment")); Bool(file->HasComment());
		Key(_T("hasUserRating")); Bool(file->HasRating());
		Key(_T("userRating")); Int(file->UserRating());
		Key(_T("hasBadRating")); Bool(file->HasBadRating());
		Key(_T("fileComment")); String(file->GetFileComment());
		Key(_T("fileRating")); Int(file->GetFileRating());
		//Object(file->getNotes());	//TODO:Object for CKadEntryPtrList
		if (!index)EndObject();
	}
	void Object(CShareableFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object((CAbstractFile*)file, index + 1);
		Key(_T("path")); String(file->GetPath());
		Key(_T("filePath")); String(file->GetFilePath());
		if (!index)EndObject();
	}
	void Object(CKnownFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object((CShareableFile*)file, index + 1);
		Key(_T("utcFileDate")); Int(file->GetUtcFileDate());
		Key(_T("isMovie")); Bool(file->IsMovie());
		Key(_T("upPriorityDisplayString")); String(file->GetUpPriorityDisplayString());
		Key(_T("utcLastModified")); Int(file->m_tUtcLastModified);
		Key(_T("completeSourcesTime")); Int(file->m_nCompleteSourcesTime);
		//Object(writer,file->m_ClientUploadList)//TODO: WriterObject for CUpDownClientPtrList
		if (!index)EndObject();
	}
	void Object(CAICHHash* hash, unsigned char index = 0) {
		//StartObject();
		String(hash->GetString());
		//EndObject();
	}
	void Object(CAICHHashTree* hash, unsigned char index = 0) {
		//StartObject();
		Object(&(hash->m_Hash));
		//EndObject();
	}
	void Object(CAICHRecoveryHashSet* hash, unsigned char index = 0) {
		//StartObject();
		Object(&(hash->m_pHashTree));
		//EndObject();
	}
	void Object(CPartFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object((CKnownFile*)file, index + 1);
		Key(_T("isPartFile")); Bool(file->IsPartFile());
		Key(_T("partMetFileName")); String(file->GetPartMetFileName());
		Key(_T("AICHHash")); Object(file->GetAICHRecoveryHashSet());
		if (!index)EndObject();
	}
};
//以上

CString WebServerRESTAPI::_GetServerList(ThreadData Data, CString& param)
{
	CWebServer *pThis = (CWebServer *)Data.pThis;
	if (pThis == NULL)
		return _T("null");
	StringBufferT s;
	JSONWriter writer(s);

	writer.StartArray();

	for (uint32 sc = 0; sc < theApp.serverlist->GetServerCount(); sc++)
	{
		CServer* cur = theApp.serverlist->GetServerAt(sc);
		writer.Object(cur);
	}
	writer.EndArray();
	return s.GetString();
}
CString WebServerRESTAPI::_GetClientList(ThreadData Data, CString& param)
{
	StringBufferT s;
	JSONWriter writer(s);
	writer.StartArray();
	theApp.clientlist->FindHeadClient();
	CUpDownClient* cur;
	while(theApp.clientlist->usedToFindByNumber != NULL) {
		cur = theApp.clientlist->FindNextClient();
		if(cur)writer.Object(cur);
	}
	writer.EndArray();
	theApp.clientlist->FindHeadClient();
	return s.GetString();
}
CString WebServerRESTAPI::_GetSharedList(ThreadData Data, CString& param)
{
	StringBufferT s;
	JSONWriter writer(s);
	writer.StartArray();
	theApp.knownfiles->FindHeadKnownFile();
	CKnownFile* cur;
	while (theApp.knownfiles->usedToFindByNumber != NULL) {
		cur = theApp.knownfiles->FindNextKnownFile();
		if (cur)writer.Object(cur);
	}
	writer.EndArray();
	theApp.knownfiles->FindHeadKnownFile();
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
	else if (sService == _T("client")) {
		pSocket->SendContent(CT2CA(JSONInit), _GetClientList(Data, sParam));
	}
	else if (sService == _T("shared")) {
		pSocket->SendContent(CT2CA(JSONInit), _GetSharedList(Data, sParam));
	}else {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
	}
}
