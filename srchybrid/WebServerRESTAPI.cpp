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

using namespace rapidjson;

#ifdef DEBUG
static const char* JSONInit = "Server: eMule REST API\r\nConnection: close\r\nContent-Type: application/json; charset=UTF-8\r\nAccess-Control-Allow-Origin: *\r\n";
#else
static const char* JSONInit = "Server: eMule REST API\r\nConnection: close\r\nContent-Type: application/json; charset=UTF-8\r\n";
#endif // DEBUG


class JSONWriter :public WriterT {
public:
	JSONWriter(StringBufferT&os) :WriterT(os) {}
	
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

	void Object(CClientCredits* credit, unsigned char index = 0) {
		if (!index)StartObject();
		Key(_T("uploadedTotal")); Uint64(credit->GetUploadedTotal());
		Key(_T("downloadedTotal")); Uint64(credit->GetDownloadedTotal());
		if (!index)EndObject();
	}
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

	void Object(CAbstractFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Key(_T("fileName")); String(file->GetFileName());
		Key(_T("fileType")); String(file->GetFileType());
		Key(_T("fileTypeDisplayName")); String(file->GetFileTypeDisplayStr());
		Key(_T("hasNullHash")); Bool(file->HasNullHash());
		Key(_T("fileHash")); String(ArrToHex(file->GetFileHash(),16));
		Key(_T("eD2kLink")); String(file->GetED2kLink());//without Hashset;HTMLTag;HostName;Source;dwSourceIP
		Key(_T("fileSize")); Uint64((uint64)(file->GetFileSize()));
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
		//Object(writer,file->m_ClientUploadList)	//TODO: WriterObject for CUpDownClientPtrList
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

const char * WebServerRESTAPI::_getStatusString(int status)
{
  switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "Non-Authoritative Information";
    case 204: return "No Content";
    case 205: return "Reset Content";
    case 206: return "Partial Content";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 305: return "Use Proxy";
      //case 306: return "(reserved)";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Request Entity Too Large";
    case 414: return "Request-URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Requested Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    default: throw CString("Not supported status code.");//这里不应该抛异常吧
  }
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
	}
	else {
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
	CString param = RawQueryString;
	CString deal = param.Tokenize(_T("&"), tokenPos);
	while (!deal.IsEmpty()) {
		int eqpos = deal.Find('=');
		if (eqpos > 0) {
			CString keyword = OptUtf8ToStr(URLDecode(deal.Left(eqpos)));
			CString value = OptUtf8ToStr(URLDecode(deal.Mid(eqpos + 1)));
			QueryString[keyword] = value;
		}
		else {
			QueryString[deal] = _T("");
		}
		deal = param.Tokenize(_T("&"), tokenPos);
	}
}

void WebServerRESTAPI::_Response(int status, LPCSTR szStdResponse, StringBufferT & data)
{
  _Response(status, szStdResponse, data.GetString(), data.GetSize());
}

void WebServerRESTAPI::_Response(int status, LPCSTR szStdResponse, const void * data, DWORD dwDataLen)
{
  CString acceptEncoding;
  bool isUseGzip;

  if (Headers.Lookup(_T("accept-encoding"), acceptEncoding) && acceptEncoding.Find(_T("gzip")) >= 0) {
    isUseGzip = true;
  } else {
    isUseGzip = false;
  }


  TCHAR* gzipOut = NULL;
  long gzipLen = 0;

  if (isUseGzip) {
    bool bOk = false;
    try {
      uLongf destLen = dwDataLen + 1024;
      gzipOut = new TCHAR[destLen];
      if (CWebServer::_GzipCompress((Bytef*)gzipOut, &destLen, (const Bytef*)data, dwDataLen, Z_DEFAULT_COMPRESSION) == Z_OK) {
        bOk = true;
        gzipLen = destLen;
      }
    }
    catch (...) {
      ASSERT(0);
    }
    if (!bOk) {
      isUseGzip = false;
      delete[] gzipOut;
      gzipOut = NULL;
    }
  }

  char szBuf[0x1000];
  if (isUseGzip) {
    int nLen = _snprintf(szBuf, _countof(szBuf),
      "HTTP/1.1 %d %s\r\n%sContent-Encoding: gzip\r\nContent-Length: %ld\r\n\r\n",
      status, _getStatusString(status), szStdResponse, gzipLen);
    if (nLen > 0) {
      Socket->SendData(szBuf, nLen);
      Socket->SendData(gzipOut, gzipLen);
    }
    delete[] gzipOut;
    gzipOut = NULL;
  } else {
    int nLen = _snprintf(szBuf, _countof(szBuf),
      "HTTP/1.1 %d %s\r\n%sContent-Length: %ld\r\n\r\n",
      status, _getStatusString(status), szStdResponse, dwDataLen);
    if (nLen > 0) {
      Socket->SendData(szBuf, nLen);
      Socket->SendData(data, dwDataLen);
    }
  }
}

#ifdef DEBUG
bool WebServerRESTAPI::_Dump()
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

  _Response(200, JSONInit, s);
  return true;
}
#endif

bool WebServerRESTAPI::_GetServerList()
{
	StringBufferT s;
	JSONWriter writer(s);

	writer.StartArray();

	for (uint32 sc = 0; sc < theApp.serverlist->GetServerCount(); sc++)
	{
		CServer* cur = theApp.serverlist->GetServerAt(sc);
		writer.Object(cur);
	}
	writer.EndArray();

  _Response(200, JSONInit, s);
  return true;
}

bool WebServerRESTAPI::_GetClientList()
{
	StringBufferT s;
	JSONWriter writer(s);

	writer.StartArray();
	theApp.clientlist->FindHeadClient();
	CUpDownClient* cur;
	while (theApp.clientlist->usedToFindByNumber != NULL) {
		cur = theApp.clientlist->FindNextClient();
		if (cur)writer.Object(cur);
	}
	writer.EndArray();
	theApp.clientlist->FindHeadClient();

  _Response(200, JSONInit, s);
	return true;
}

bool WebServerRESTAPI::_GetSharedList()
{
	StringBufferT s;
	JSONWriter writer(s);

	writer.StartArray();
	theApp.sharedfiles->FindHeadKnownFile();
	CKnownFile* cur;
	while (theApp.sharedfiles->usedToFindByNumber != NULL) {
		cur = theApp.sharedfiles->FindNextKnownFile();
		if (cur)writer.Object(cur);
	}
	writer.EndArray();
	theApp.sharedfiles->FindHeadKnownFile();

  _Response(200, JSONInit, s);
  return true;
}

bool WebServerRESTAPI::_GetknownfList()
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

  _Response(200, JSONInit, s);
  return true;
}

// TODO: 这里函数名貌似不对?
bool ProgressEd2KLink(CString & link, CString & action) {
	CString type;
	int iStart = 0;
	type = link.Tokenize(_T("|"), iStart);
	type = link.Tokenize(_T("|"), iStart);
	if (_T("friend") == type) {
		if (_T("add") == action) {
			theApp.emuledlg->ProcessED2KLink(link);
		}
		else if (_T("del") == action) {
			return false;
		}
	}
	else if (_T("server") == type) {
		if (_T("add") == action) {
			theApp.emuledlg->ProcessED2KLink(link);
		}
		else if (_T("del") == action) {
			return false;
		};
		return true;
	}
}

// TODO: 这里可以根据兔子那边增加的请求头处理函数处理后的数据来优化代码结构
bool WebServerRESTAPI::_Action(CMapStringToString & list, CString action)
{
	do {
		CString link;
		if (list.Lookup(_T("link"), link)) {
			int iStart = 0;
			CString type;
			type = link.Tokenize(_T(":"), iStart);
			if (_T("ed2k") == type) {
				if (ProgressEd2KLink(link, action)) {
					//TODO:添加处理成功后的返回
					break;
				}
				else {
					break;
				}
			}
			else if (_T("file") == type) {
				break;
			}
			else if (_T("http") == type) {
				break;
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	} while (0);
	return true;
}

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

	// 处理访问根路径的情况
	if (Path.GetCount() == 0) return false;

	//TODO: 在这里增加共享文件,下载文件,上传队列,下载队列等处理,用if...else if...else的形式
	if (Path[0] == _T("server")) {
		return _GetServerList();
	}
	else if (Path[0] == _T("client")) {
		return _GetClientList();
	}
	else if (Path[0] == _T("shared")) {
		return _GetSharedList();
	}
	else if (Path[0] == _T("knownf")) {
		return _GetknownfList();
	}
	else if (Path[0] == _T("action")) {
		if (Path.GetCount() == 2) {
			return _Action(QueryString, Path[1]);
		}
		else {
			return false;
		}
	}
	else if (Path[0] == _T("dump")) {
#ifdef DEBUG
		return _Dump();
#else
		return false;
#endif
	}
	else {
		return false;
	}
}
