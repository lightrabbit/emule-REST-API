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
//������Ҫ����emule�İ汾������������һ���ṩ����ϵͳ�ȵ���Ϣ�� By ����
static const TCHAR* JSONInit = _T("Server: eMule\r\nConnection: close\r\nContent-Type: application/json; charset=UTF-8\r\n");
//WriteObjectӦ�ö�ȡ��Щ��������ݣ�
//TODO: Doing-���ú괦��������write.Key����������


static void WriteObject(WriterT& writer, CServer* server)
{
	writer.StartObject();
	writer.Key(_T("listName")); writer.String(server->GetListName());//name��Ϊlistname
	writer.Key(_T("address")); writer.String(server->GetAddress());//ip��Ϊaddress By ����
	writer.Key(_T("port")); writer.Uint(server->GetPort());
	writer.Key(_T("description")); writer.String(server->GetDescription());
	//TODO: ����ʮ��������û�ӽ���	--����� ���ظ�����ɾ�� By Yuzu
	//Notice:����������������д���벻Ҫ��������һ���ַ�
	//����Server.h�����CServer���ṩ�ĺ�����д
	//����CServer�ṩ�����Ծ������ @ 2016-5-24 01��03
	//�ƺ��в����������ظ��ģ�����ȥ����������ֶ�����IP���ԣ�
	//��ֱ��ʹ�úͺ���һ�µ�����
	//��������GetXXX->XXX;HasXXX->hasXXX;Bool����ǰ�油��is	@23��21
	writer.Key(_T("dynIP")); writer.String(server->GetDynIP());
	writer.Key(_T("IP"));	writer.Uint(server->GetIP());
	writer.Key(_T("hasDynIP")); writer.Bool(server->HasDynIP());
	writer.Key(_T("fullIP")); writer.String(server->GetFullIP());
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
	//�Ա�CServer�������������Ե�������--�����@ 2016-5-25 10��10
	//�ٴ�ɾ�����ظ��
	writer.EndObject();
}

//�����ڳ���дһ�����غ��ѵĺ�������Ϊ�����б�����Ҫ���ص�������Զ���
//�Һ�Ȼ�뵽 WriteObiect�ĺ��������������壬
//������ǰ�˲������󣨱������Ӻ��ѣ��ĺ������ظ���@ 2016-5-24 3��00
//CFriend��ķ����CServer��ķ����һ�����죬��Ҫע��һ�¡�

//TODO:���CUpDownClient���͵ķ���
//list=CClientList
static void WriteObject(WriterT& writer, CUpDownClient* client, unsigned char index = 0)
{ //��ע�⵽CUpDownClient������GetFriend()��������CFriend�� 
  //CFriend������GetLinkedClient()��������CUpDownClient��
  //��β��ܱ������޵ݹ飿
  //һ�����еķ����ǣ�����WriteObject�е��õ�WriteObject������ֻ����������Ϣ����������ϸ��Ϣ


	if (index) {
		writer.Key(_T("clientUserHash")); writer.String(CString(client->GetUserHash()));//uchar[16]
	}
	else {
		writer.StartObject();
		writer.Key(_T("Client")); writer.String(_T("NotSupportted"));
		writer.EndObject();
	}

}

static void WriteObject(WriterT& writer, CFriend* pail)//��Ϊfriend�ǹؼ��֣�������pail 
{
	CUpDownClient* Client;
	Client = pail->GetLinkedClient();

	writer.StartObject();
	writer.Key(_T("userHash")); writer.String(CString(pail->m_abyUserhash));//uchar[16]
	writer.Key(_T("lastSeen")); writer.Int64(pail->m_dwLastSeen);//�п�����64λʱ��
	writer.Key(_T("lastUsedIP")); writer.Int(pail->m_dwLastUsedIP);
	writer.Key(_T("lastUsedPort")); writer.Int(pail->m_nLastUsedPort);
	writer.Key(_T("lastChatted")); writer.Int(pail->m_dwLastChatted);
	writer.Key(_T("name")); writer.String(pail->m_strName);
	//TODO:����GetLinkedClient();�ķ��͸�ʽ��ʵ��	--׼������
	WriteObject(writer, Client);//TODO: WriteObject for CUpDownClient
	//�Լ�GetClientForChatSession();�Ĺ��ܼ�ʵ��
	writer.Key(_T("isTryToConnet")); writer.Bool(pail->IsTryingToConnect());
	writer.Key(_T("isFriendSlotted")); writer.Bool(pail->GetFriendSlot());
	writer.Key(_T("hasUserHash")); writer.Bool(pail->HasUserhash());
	writer.Key(_T("hasKadID")); writer.Bool(pail->HasKadID());

	writer.EndObject();
}
//�ƺ�����CFriend����ȫû�б�Ҫ�ģ�����CUpDownClient��ͺ���
//����Ҳ��isFriend�����������Ҫ��������Friend��ͨ����ѯ����
//isFriend()=Ture��Client�ͺ�


static void WriteObject(WriterT& writer, CAbstractFile* file, unsigned char index = 0 ) {
    if (!index)writer.StartObject();
	writer.Key(_T("fileName")); writer.String(file->GetFileName());
	writer.Key(_T("fileType")); writer.String(file->GetFileType());
	writer.Key(_T("fileTypeDisplayName")); writer.String(file->GetFileTypeDisplayStr());
	//WriteObject(writer,file->GetFileIdentifier());	//TODO: WriteObject for CFileIdentifier
	writer.Key(_T("fileHash")); writer.String(CString(file->GetFileHash()));
	writer.Key(_T("hasHashSet")); writer.Bool(file->HasNullHash());
	writer.Key(_T("eD2kLink")); writer.String(file->GetED2kLink());//without Hashset;HTMLTag;HostName;Source;dwSourceIP
	//WriteObject(writer,file->GetFileSize());	//TODO: WriteObject for EMFileSize
	writer.Key(_T("isLargeFile")); writer.Bool(file->IsLargeFile());
	writer.Key(_T("isPartfile")); writer.Bool(file->IsPartFile());
	writer.Key(_T("hasComment")); writer.Bool(file->HasComment());
	writer.Key(_T("userRating")); writer.Int(file->UserRating());
	writer.Key(_T("hasUserRating")); writer.Bool(file->HasRating());
	writer.Key(_T("hasBadRating")); writer.Bool(file->HasBadRating());
	writer.Key(_T("fileComment")); writer.String(file->GetFileComment());
	writer.Key(_T("fileRating")); writer.Int(file->GetFileRating());
	//WriteObject(writer, file->getNotes());	//TODO:WriteObject for CKadEntryPtrList
	writer.Key(_T("isKadCommentSearchRunning")); writer.Bool(file->IsKadCommentSearchRunning());
	writer.Key(_T("isCompressible")); writer.Bool(file->IsCompressible());
	if (!index)writer.EndObject();
}
static void WriteObject(WriterT& writer, CShareableFile* file, unsigned char index = 0) {
	if (!index)writer.StartObject();
	WriteObject(writer, (CAbstractFile*)file, index+1);
	//WriteObject(writer,file->GetVerifiedFileType());	//TODO:WriteObject for EFileType
	writer.Key(_T("isPartfile")); writer.Bool(file->IsPartFile());
	writer.Key(_T("path")); writer.String(file->GetPath());
	writer.Key(_T("sharedDirectory")); writer.String(file->GetSharedDirectory());
	writer.Key(_T("isShellLinked")); writer.Bool(file->IsShellLinked());
	writer.Key(_T("filePath")); writer.String(file->GetFilePath());
	writer.Key(_T("infoSummary")); writer.String(file->GetInfoSummary());
	if (!index)writer.EndObject();
}

//��typeid(����)�������ͣ����������
//����

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
	int iStart = 6;	//Magic number����
	CString sService = Data.sURL.Tokenize(_T("/"), iStart);
	CString sParam = Data.sURL.Mid(iStart);
	//TODO: ���������ӹ����ļ�,�����ļ�,�ϴ�����,���ض��еȴ���,��if...else if...else����ʽ
	if (sService == _T("server")) {
		pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
	}
	else if (sService == _T("friend")) {
		//pSocket->SendContent(CT2CA(JSONInit), _GetServerList(Data, sParam));
		//TODO: ��ȡfriendlist
		;
	}
	else {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
	}
}
