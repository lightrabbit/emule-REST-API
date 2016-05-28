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
//TODO: Doing-采用宏处理批量的write.Key及后面的语句


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
static void WriteObject(WriterT& writer, CClientCredits* credit, unsigned char index = 0,CUpDownClient* client=NULL) {
	if (!index)writer.StartObject();
	writer.Key(_T("uploadedTotal")); writer.Uint64(credit->GetUploadedTotal());
	writer.Key(_T("downloadedTotal")); writer.Uint64(credit->GetDownloadedTotal());
	if (client) {
		bool ans = credit->GetHasScore(client);
		writer.Key(_T("hasScore")); writer.Bool(ans);
		if (ans) {
			writer.Key(_T("currentIdentState")); writer.Uint(credit->GetCurrentIdentState(client->GetIP()));
			/*
			enum EIdentState{
				IS_NOTAVAILABLE,
				IS_IDNEEDED,
				IS_IDENTIFIED,
				IS_IDFAILED,
				IS_IDBADGUY,
			};
			*/
		}

	}
	if (!index)writer.EndObject();
}
//TODO:完成CUpDownClient类型的返回
//list=CClientList
static void WriteObject(WriterT& writer, CUpDownClient* client, unsigned char index = 0)
{ //我注意到CUpDownClient类中有GetFriend()方法返回CFriend类 
  //CFriend类中有GetLinkedClient()方法返回CUpDownClient类
  //如何才能避免无限递归？
  //一个可行的方法是，所有WriteObject中调用的WriteObject方法，只返回索引信息，不返回详细信息


	if (index) {
		writer.Key(_T("clientUserHash")); writer.String(CString(client->GetUserHash()));//uchar[16]
	}
	else {
		writer.StartObject();


		writer.Key(_T("uploadDatarate")); writer.Uint(client->GetUploadDatarate());
		writer.Key(_T("userHash")); writer.String(CString(client->GetUserHash()));
		writer.Key(_T("clientVersion")); writer.Int(client->GetClientSoft());
		writer.Key(_T("isBanned")); writer.Bool(client->IsBanned());
		writer.Key(_T("userName")); writer.String(CString(client->GetUserName()));
		writer.Key(_T("SoftVer")); writer.String(client->GetClientSoftVer());
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
		writer.Key(_T("IP")); writer.Int(client->GetIP());//
		writer.Key(_T("isFriend")); writer.Bool(client->IsFriend());
		WriteObject(writer, client->CheckAndGetReqUpFile());//CKnownFile
		writer.Key(_T("transferredUp")); writer.Int(client->GetTransferredUp());
		writer.Key(_T("transferredDown")); writer.Int(client->GetTransferredDown());
		writer.Key(_T("clientModVer")); writer.String(client->GetClientModVer());
		writer.Key(_T("version")); writer.Int(client->GetVersion());
		writer.Key(_T("muleVersion")); writer.Int(client->GetMuleVersion());

		WriteObject(writer, client->Credits(),index+1,client);	//TODO: !!!WriteObject for CClientCredits


		/*//先全部注释掉吧
		writer.Key(_T("Client")); writer.String(_T("NotSupporttedYet"));
		writer.Key(_T("isEd2kClient")); writer.Bool(client->IsEd2kClient());
		writer.Key(_T("checkHandshakeFinished")); writer.Bool(client->CheckHandshakeFinished());
		writer.Key(_T("userIDHybrid")); writer.Int(client->GetUserIDHybrid());
		
		writer.Key(_T("hasLowID")); writer.Bool(client->HasLowID());
		writer.Key(_T("connectIP")); writer.Int(client->GetConnectIP());
		writer.Key(_T("userPort")); writer.Int(client->GetUserPort());

		writer.Key(_T("serverIP")); writer.Int(client->GetServerIP());
		writer.Key(_T("serverPort")); writer.Int(client->GetServerPort());
		writer.Key(_T("userHash")); writer.String(CString(client->GetUserHash()));
		writer.Key(_T("hasValidHash")); writer.Bool(client->HasValidHash());
		writer.Key(_T("hashType")); writer.Int(client->GetHashType());
		writer.Key(_T("buddyID")); writer.String(CString(client->GetBuddyID()));
		writer.Key(_T("hasValidBuddyID")); writer.Bool(client->HasValidBuddyID());
		writer.Key(_T("buddyIP")); writer.Int(client->GetBuddyIP());
		writer.Key(_T("buddyPort")); writer.Int(client->GetBuddyPort());
		//WriteObject(writer,client->GetClientSoft());	//TODO: !!!WriteObject for EClientSoftware

		writer.Key(_T("isExtProtocolAvailable")); writer.Bool(client->ExtProtocolAvailable());
		writer.Key(_T("isSupportMultiPacket")); writer.Bool(client->SupportMultiPacket());
		writer.Key(_T("isSupportExtMultiPacket")); writer.Bool(client->SupportExtMultiPacket());
		writer.Key(_T("isSupportPeerCache")); writer.Bool(client->SupportPeerCache());
		writer.Key(_T("isSupportsLargeFiles")); writer.Bool(client->SupportsLargeFiles());
		writer.Key(_T("isSupportsFileIdentifiers")); writer.Bool(client->SupportsFileIdentifiers());
		writer.Key(_T("isEmuleClient")); writer.Bool(client->IsEmuleClient());
		writer.Key(_T("sourceExchange1Version")); writer.Int(client->GetSourceExchange1Version());
		writer.Key(_T("isSupportsSourceExchange2")); writer.Bool(client->SupportsSourceExchange2());
		
		writer.Key(_T("clientFilename")); writer.String(client->GetClientFilename());
		writer.Key(_T("uDPPort")); writer.Int(client->GetUDPPort());
		writer.Key(_T("uDPVersion")); writer.Int(client->GetUDPVersion());
		writer.Key(_T("isSupportsUDP")); writer.Bool(client->SupportsUDP());
		writer.Key(_T("kadPort")); writer.Int(client->GetKadPort());
		writer.Key(_T("extendedRequestsVersion")); writer.Int(client->GetExtendedRequestsVersion());
		//WriteObject(writer, client->GetConnectingState());//TODO: !!!WriterObject for EConnectingState
		writer.Key(_T("lastSrcReqTime")); writer.Int(client->GetLastSrcReqTime());
		writer.Key(_T("lastSrcAnswerTime")); writer.Int(client->GetLastSrcAnswerTime());
		writer.Key(_T("lastAskedForSources")); writer.Int(client->GetLastAskedForSources());
		writer.Key(_T("friendSlot")); writer.Bool(client->GetFriendSlot());
		writer.Key(_T("isFriend")); writer.Bool(client->IsFriend());

		//WriteObject(writer, client->GetFriend(),index+1);//警告：可能产生无穷递归

		writer.Key(_T("sentCancelTransfer")); writer.Bool(client->GetSentCancelTransfer());
		writer.Key(_T("kadVersion")); writer.Int(client->GetKadVersion());
		writer.Key(_T("isSendBuddyPingPong")); writer.Bool(client->SendBuddyPingPong());
		writer.Key(_T("isAllowIncomeingBuddyPingPong")); writer.Bool(client->AllowIncomeingBuddyPingPong());
		writer.Key(_T("secureIdentState")); writer.Int(client->GetSecureIdentState());
		writer.Key(_T("infoPacketsReceived")); writer.Bool(client->GetInfoPacketsReceived());
		writer.Key(_T("isSupportPreview")); writer.Bool(client->GetPreviewSupport());
		writer.Key(_T("isSupportViewSharedFiles")); writer.Bool(client->GetViewSharedFilesSupport());
		writer.Key(_T("isRequestsCryptLayer")); writer.Bool(client->RequestsCryptLayer());
		writer.Key(_T("isRequiresCryptLayer")); writer.Bool(client->RequiresCryptLayer());
		writer.Key(_T("isSupportsDirectUDPCallback")); writer.Bool(client->SupportsDirectUDPCallback());
		writer.Key(_T("isObfuscatedConnectionEstablished")); writer.Bool(client->IsObfuscatedConnectionEstablished());
		writer.Key(_T("isShouldReceiveCryptUDPPackets")); writer.Bool(client->ShouldReceiveCryptUDPPackets());
		WriterObject(writer, client->GetUploadState());	//TODO: WriterObject for EUploadState
		writer.Key(_T("waitStartTime")); writer.Int64(client->GetWaitStartTime());
		writer.Key(_T("waitTime")); writer.Int(client->GetWaitTime());
		writer.Key(_T("isDownloading")); writer.Bool(client->IsDownloading());
		writer.Key(_T("hasBlocks")); writer.Bool(client->HasBlocks());
		writer.Key(_T("numberOfRequestedBlocksInQueue")); writer.Uint(client->GetNumberOfRequestedBlocksInQueue());
		writer.Key(_T("upStartTimeDelay")); writer.Uint(client->GetUpStartTimeDelay());
		writer.Key(_T("uploadFileID")); writer.String(CString(client->GetUploadFileID()));
		writer.Key(_T("sendBlockData")); writer.Uint(client->SendBlockData());
		writer.Key(_T("askedCount")); writer.Uint(client->GetAskedCount());
		writer.Key(_T("lastUpRequest")); writer.Uint(client->GetLastUpRequest());
		writer.Key(_T("hasCollectionUploadSlot")); writer.Bool(client->HasCollectionUploadSlot());
		writer.Key(_T("sessionUp")); writer.Uint(client->GetSessionUp());
		writer.Key(_T("sessionPayloadDown")); writer.Uint(client->GetSessionPayloadDown());
		writer.Key(_T("queueSessionPayloadUp")); writer.Bool(client->GetQueueSessionPayloadUp());
		writer.Key(_T("payloadInBuffer")); writer.Bool(client->GetPayloadInBuffer());
		writer.Key(_T("upPartCount")); writer.Uint(client->GetUpPartCount());
		writer.Key(_T("upPartStatus")); writer.Uint(*(client->GetUpPartStatus()));
		writer.Key(_T("combinedFilePrioAndCredit")); writer.Double(client->GetCombinedFilePrioAndCredit());
		writer.Key(_T("askedCountDown")); writer.Int(client->GetAskedCountDown());
		//WriteObject(writer,client->GetDownloadState());	//TODO: WriterObject for EDownloadState
		writer.Key(_T("partStatus")); writer.Uint(*(client->GetPartStatus()));
		writer.Key(_T("partCount")); writer.Uint(client->GetPartCount());
		writer.Key(_T("remoteQueueRank")); writer.Int(client->GetRemoteQueueRank());
		writer.Key(_T("isRemoteQueueFull")); writer.Bool(client->IsRemoteQueueFull());
		writer.Key(_T("availablePartCount")); writer.Int(client->GetAvailablePartCount());
		writer.Key(_T("uDPPacketPending")); writer.Int(client->UDPPacketPending());
		writer.Key(_T("isSourceRequestAllowed")); writer.Int(client->IsSourceRequestAllowed());
		writer.Key(_T("isValidSource")); writer.Int(client->IsValidSource());
		//WriterObject(writer.client->GetSourceFrom());	//TODO: WriterObject for ESourceFrom
		writer.Key(_T("upCompleteSourcesCount")); writer.Int(client->GetUpCompleteSourcesCount());
		//WriterObject(writer,client->GetChatState());	//TODO:WriterObject for EChatState
		//WriterObject(writer,client->GetChatCaptchaState());	//TODO:WriterObject for EChatCaptchaState
		writer.Key(_T("messagesReceived")); writer.Int(client->GetMessagesReceived());
		writer.Key(_T("messagesSent")); writer.Int(client->GetMessagesSent());
		writer.Key(_T("isSpammer")); writer.Bool(client->IsSpammer());
		writer.Key(_T("messageFiltered")); writer.Bool(client->GetMessageFiltered());
		//WriterObject(writer,client->GetKadState());	//TODO: WriterObject for EKadState
		writer.Key(_T("hasFileComment")); writer.Bool(client->HasFileComment());
		writer.Key(_T("fileComment")); writer.String(client->GetFileComment());
		writer.Key(_T("hasFileRating")); writer.Bool(client->HasFileRating());
		writer.Key(_T("reqFileAICHHash")); WriteObject(writer, client->GetReqFileAICHHash());
		writer.Key(_T("isSupportingAICH")); writer.Bool(client->IsSupportingAICH());
		writer.Key(_T("isAICHReqPending")); writer.Bool(client->IsAICHReqPending());
		//WriterObject(writer,client->GetUnicodeSupport());	//TODO: WriterObject for EUtf8Str
		writer.Key(_T("downloadStateDisplayString")); writer.String(client->GetDownloadStateDisplayString());
		writer.Key(_T("uploadStateDisplayString")); writer.String(client->GetUploadStateDisplayString());
		//WriterObject(writer,client->credits);	//TODO: WriterObject for CClientCredits
		//WriterObject(writer,clienr->m_OtherRequests_list);
		//WriterObject(writer,clienr->m_OtherNoNeeded_list);	//TODO: WriterObject for CTypedPtrList<CPtrList, CPartFile*>
		writer.Key(_T("lastPartAsked")); writer.Int(client->m_lastPartAsked);
		writer.Key(_T("addNextConnect")); writer.Bool(client->m_bAddNextConnect);
		writer.Key(_T("isDownloadingFromPeerCache")); writer.Bool(client->IsDownloadingFromPeerCache());
		writer.Key(_T("isUploadingToPeerCache")); writer.Bool(client->IsUploadingToPeerCache());
		writer.Key(_T("hasPeerCacheState")); writer.Bool(client->HasPeerCacheState());
		writer.Key(_T("httpSendState")); writer.Int(client->GetHttpSendState());
		writer.Key(_T("sendPeerCacheFileRequest")); writer.Bool(client->SendPeerCacheFileRequest());
		writer.Key(_T("onPeerCacheDownSocketTimeout")); writer.Bool(client->OnPeerCacheDownSocketTimeout());
		writer.Key(_T("upendsoon")); writer.Bool(client->upendsoon);
		writer.Key(_T("isDifferentPartBlock")); writer.Bool(client->IsDifferentPartBlock());
		writer.Key(_T("remainingBlocksToDownload")); writer.Bool(client->GetRemainingBlocksToDownload());
		writer.Key(_T("")); writer.Bool(client->());
		//*/
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
	WriteObject(writer, Client);//TODO: WriteObject for CUpDownClient
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
static void WriteObject(WriterT& writer, CKnownFile* file, unsigned char index = 0) {
	if (!index)writer.StartObject();
	WriteObject(writer, (CShareableFile*)file, index + 1);
	//WriteObject(writer,file->GetUtcCFileDate);
	writer.Key(_T("utcFileDate")); writer.Int(file->GetUtcFileDate());
	writer.Key(_T("isShouldPartiallyPurgeFile")); writer.Bool(file->ShouldPartiallyPurgeFile());
	writer.Key(_T("partCount")); writer.Int(file->GetPartCount());
	writer.Key(_T("eD2KPartCount")); writer.Int(file->GetED2KPartCount());
	writer.Key(_T("upPriority")); writer.Int(file->GetUpPriority());
	writer.Key(_T("upPriorityEx")); writer.Int(file->GetUpPriorityEx());
	writer.Key(_T("isAutoUpPriority")); writer.Bool(file->IsAutoUpPriority());
	writer.Key(_T("calculateUploadPriorityPercent")); writer.Double(file->CalculateUploadPriorityPercent());
	writer.Key(_T("wantedUpload")); writer.Int64(file->GetWantedUpload());
	writer.Key(_T("pushfaktor")); writer.Double(file->pushfaktor);
	writer.Key(_T("virtualUploadSources")); writer.Int(file->m_nVirtualUploadSources);
	writer.Key(_T("virtualSourceIndicator")); writer.Int(file->GetVirtualSourceIndicator());
	writer.Key(_T("virtualCompleteSourcesCount")); writer.Int(file->m_nVirtualCompleteSourcesCount);
	writer.Key(_T("getOnUploadqueue")); writer.Int(file->GetOnUploadqueue());
	writer.Key(_T("isPublishedED2K")); writer.Bool(file->GetPublishedED2K());
	writer.Key(_T("kadFileSearchID")); writer.Int(file->GetKadFileSearchID());
	//WriteObject(writer,file->GetKadKeywords())	//TODO: WriteObjects for Kademlia::WordList
	writer.Key(_T("lastPublishTimeKadSrc")); writer.Int(file->GetLastPublishTimeKadSrc());
	writer.Key(_T("lastPublishBuddy")); writer.Int(file->GetLastPublishBuddy());
	writer.Key(_T("lastPublishTimeKadNotes")); writer.Int(file->GetLastPublishTimeKadNotes());
	writer.Key(_T("hasPublishSrc")); writer.Bool(file->PublishSrc());
	writer.Key(_T("hasPublishNotes")); writer.Int(file->PublishNotes());
	writer.Key(_T("metaDataVer")); writer.Int(file->GetMetaDataVer());
	writer.Key(_T("isMovie")); writer.Bool(file->IsMovie());
	writer.Key(_T("infoSummary")); writer.String(file->GetInfoSummary());
	writer.Key(_T("upPriorityDisplayString")); writer.String(file->GetUpPriorityDisplayString());
	writer.Key(_T("isAICHRecoverHashSetAvailable")); writer.Bool(file->IsAICHRecoverHashSetAvailable());
	writer.Key(_T("utcLastModified")); writer.Int(file->m_tUtcLastModified);
	//WriteObject(writer,file->statistic)	//TODO: WriteObjects for CStatisticFile
	writer.Key(_T("completeSourcesTime")); writer.Int(file->m_nCompleteSourcesTime);
	writer.Key(_T("completeSourcesCount")); writer.Int(file->m_nCompleteSourcesCount);
	writer.Key(_T("completeSourcesCountLo")); writer.Int(file->m_nCompleteSourcesCountLo);
	writer.Key(_T("completeSourcesCountHi")); writer.Int(file->m_nCompleteSourcesCountHi);
	//WriteObject(writer,file->m_ClientUploadList)//TODO: WriterObject for CUpDownClientPtrList
	//WriteObject(writer,file->m_AvailPartFrequency)//TODO: WriteObject for CArray<uint16, uint16> 
	//WriteObject(writer,file->m_pCollection)//TODO: WriteObject for CCollection*
	writer.Key(_T("isSR13_ImportParts")); writer.Bool(file->SR13_ImportParts());
	writer.Key(_T("startUploadTime")); writer.Int(file->GetStartUploadTime());
	writer.Key(_T("fileRatio")); writer.Double(file->GetFileRatio());
	writer.Key(_T("isPushSmallFile")); writer.Bool(file->IsPushSmallFile());
	writer.Key(_T("feedback")); writer.String(file->GetFeedback());
	//WriteObject(writer,file->m_PartSentCount)//TODO: WriteObject for CArray<uint64> 
	writer.Key(_T("hideOS")); writer.Int(file->GetHideOS());
	writer.Key(_T("selectiveChunk")); writer.Int(file->GetSelectiveChunk());
	writer.Key(_T("hideOSInWork")); writer.Int(file->HideOSInWork());
	writer.Key(_T("shareOnlyTheNeed")); writer.Int(file->GetShareOnlyTheNeed());
	writer.Key(_T("sotnInWork")); writer.Int(file->SotnInWork());
	writer.Key(_T("powerSharedMode")); writer.Int(file->GetPowerSharedMode());
	writer.Key(_T("ispowerShareAuthorized")); writer.Bool(file->GetPowerShareAuthorized());
	writer.Key(_T("ispowerShareAuto")); writer.Bool(file->GetPowerShareAuto());
	writer.Key(_T("powerShareLimit")); writer.Int(file->GetPowerShareLimit());
	writer.Key(_T("ispowerShareLimited")); writer.Bool(file->GetPowerShareLimited());
	writer.Key(_T("ispowerShared")); writer.Bool(file->GetPowerShared());
	writer.Key(_T("knownStyle")); writer.Int(file->GetKnownStyle());
	writer.Key(_T("psAmountLimit")); writer.Int(file->GetPsAmountLimit());
	if (!index)writer.EndObject();
}
static void WriteObject(WriterT& writer, CAICHHash* hash, unsigned char index = 0) {
	//writer.StartObject();
	writer.String(hash->GetString());
	//writer.EndObject();
}
static void WriteObject(WriterT& writer, CAICHHashTree* hash, unsigned char index = 0) {
	//writer.StartObject();
	WriteObject(writer, &(hash->m_Hash));
	//writer.EndObject();
}
static void WriteObject(WriterT& writer, CAICHRecoveryHashSet* hash, unsigned char index = 0) {
	//writer.StartObject();
	WriteObject(writer, &(hash->m_pHashTree));
	//writer.EndObject();
}
static void WriteObject(WriterT& writer, CPartFile* file, unsigned char index = 0) {
	if (!index)writer.StartObject();
	WriteObject(writer, (CKnownFile*)file, index + 1);
	writer.Key(_T("isPartFile")); writer.Bool(file->IsPartFile());
	writer.Key(_T("partMetFileName")); writer.String(file->GetPartMetFileName());
	writer.Key(_T("AICHHash")); WriteObject(writer, file->GetAICHRecoveryHashSet());
	if (!index)writer.EndObject();
}


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
	else if (sService == _T("client")) {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("Not Supportt /client Yet")));
	}
	else if (sService == _T("shared")) {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("Not Supportt /shared Yet")));
	}else {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
	}
}
