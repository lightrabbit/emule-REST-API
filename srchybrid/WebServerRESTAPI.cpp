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
	//TODO: Doing-采用宏处理批量的write.Key及后面的语句
	void Object(WriterT& writer, CServer* server){
		StartObject();
		Key(_T("listName")); String(server->GetListName());//name改为listname
		Key(_T("address")); String(server->GetAddress());//ip改为address By 柚子
		Key(_T("port")); Uint(server->GetPort());
		Key(_T("description")); String(server->GetDescription());
		//TODO: 还有十几个属性没加进来	--已添加 ，重复项已删除 By Yuzu
		//Notice:以下是新手柚子所写，请不要相信哪怕一个字符
		//根据Server.h定义的CServer类提供的函数编写
		//所有CServer提供的属性均已添加 @ 2016-5-24 01：03
		//似乎有部分属性是重复的，可以去掉（例如多种多样的IP属性）
		//将直接使用和函数一致的名字
		//命名规则：GetXXX->XXX;HasXXX->hasXXX;Bool的在前面补充is	@23：21
		Key(_T("dynIP")); String(server->GetDynIP());
		Key(_T("IP"));	Uint(server->GetIP());
		Key(_T("hasDynIP")); Bool(server->HasDynIP());
		Key(_T("fullIP")); String(server->GetFullIP());
		Key(_T("files")); Uint(server->GetFiles());
		Key(_T("users")); Uint(server->GetUsers());
		Key(_T("preference")); Uint(server->GetPreference());
		Key(_T("ping")); Uint(server->GetPing());
		Key(_T("maxUsers")); Uint(server->GetMaxUsers());
		Key(_T("failedCount")); Uint(server->GetFailedCount());
		Key(_T("lastPingedTime")); Uint(server->GetLastPingedTime());
		Key(_T("realLastPingedTime")); Uint(server->GetRealLastPingedTime());
		Key(_T("gastPinged")); Uint(server->GetLastPinged());
		Key(_T("lastDescPingedCount")); Uint(server->GetLastDescPingedCount());
		Key(_T("isStaticMember")); Bool(server->IsStaticMember());
		Key(_T("challenge")); Uint(server->GetChallenge());
		Key(_T("descReqChallenge")); Uint(server->GetDescReqChallenge());
		Key(_T("softFiles")); Uint(server->GetSoftFiles());
		Key(_T("hardFiles")); Uint(server->GetHardFiles());
		Key(_T("version")); String(server->GetVersion());
		Key(_T("tCPFlags")); Uint(server->GetTCPFlags());
		Key(_T("uDPFlags")); Uint(server->GetUDPFlags());//感觉这里命名有什么不对 By 柚子
		Key(_T("lowIDUsers")); Uint(server->GetLowIDUsers());
		Key(_T("obfuscationPortTCP")); Uint(server->GetObfuscationPortTCP());
		Key(_T("obfuscationPortUDP")); Uint(server->GetObfuscationPortUDP());
		Key(_T("serverKeyUDP")); Uint(server->GetServerKeyUDP());
		Key(_T("isCryptPingReplyPending")); Bool(server->GetCryptPingReplyPending());
		Key(_T("serverKeyUDPIP")); Uint(server->GetServerKeyUDPIP());
		Key(_T("isSupportsUnicode")); Bool(server->GetUnicodeSupport());
		Key(_T("isSupportsRelatedSearch")); Bool(server->GetRelatedSearchSupport());
		Key(_T("isSupportsLargeFilesTCP")); Bool(server->SupportsLargeFilesTCP());
		Key(_T("isSupportsLargeFilesUDP")); Bool(server->SupportsLargeFilesUDP());
		Key(_T("isSupportsObfuscationUDP")); Bool(server->SupportsObfuscationUDP());
		Key(_T("isSupportsObfuscationTCP")); Bool(server->SupportsObfuscationTCP());
		Key(_T("isSupportsGetSourcesObfuscation")); Bool(server->SupportsGetSourcesObfuscation());

		//修改了部分布尔变量的key名，使其更加一致
		//同时我也看出来eMule的代码是如何坑爹的@ 2016-5-24 01：03
		//对比CServer类检查了上面属性的完整性--已完成@ 2016-5-25 10：10
		//再次删除了重复项。
		EndObject();
	}

	//我正在尝试写一个返回好友的函数，因为好友列表所需要返回的数据相对独立
	//我忽然想到 WriteObiect的函数名或许有歧义，
	//可能与前端操作对象（比如增加好友）的函数名重复？@ 2016-5-24 3：00
	//CFriend类的风格与CServer类的风格有一定差异，需要注意一下。
	void Object(WriterT& writer, CClientCredits* credit, unsigned char index = 0, CUpDownClient* client = NULL) {
		if (!index)StartObject();
		Key(_T("uploadedTotal")); Uint64(credit->GetUploadedTotal());
		Key(_T("downloadedTotal")); Uint64(credit->GetDownloadedTotal());
		if (client) {
			bool ans = credit->GetHasScore(client);
			Key(_T("hasScore")); Bool(ans);
			if (ans) {
				Key(_T("currentIdentState")); Uint(credit->GetCurrentIdentState(client->GetIP()));
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
		if (!index)EndObject();
	}
	//TODO:完成CUpDownClient类型的返回
	//list=CClientList
	void Object(WriterT& writer, CUpDownClient* client, unsigned char index = 0)
	{ //我注意到CUpDownClient类中有GetFriend()方法返回CFriend类 
	  //CFriend类中有GetLinkedClient()方法返回CUpDownClient类
	  //如何才能避免无限递归？
	  //一个可行的方法是，所有Object中调用的Object方法，只返回索引信息，不返回详细信息


		//if (index)
		{
			Key(_T("clientUserHash")); String(CString(client->GetUserHash()));//uchar[16]
		}
		//else
		{
			StartObject();


			Key(_T("uploadDatarate")); Uint(client->GetUploadDatarate());
			Key(_T("userHash")); String(CString(client->GetUserHash()));
			Key(_T("clientVersion")); Int(client->GetClientSoft());
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
			Key(_T("IP")); Int(client->GetIP());//
			Key(_T("isFriend")); Bool(client->IsFriend());
			//Object(writer, client->CheckAndGetReqUpFile());//CKnownFile
			Key(_T("transferredUp")); Int(client->GetTransferredUp());
			Key(_T("transferredDown")); Int(client->GetTransferredDown());
			Key(_T("clientModVer")); String(client->GetClientModVer());
			Key(_T("version")); Int(client->GetVersion());
			Key(_T("muleVersion")); Int(client->GetMuleVersion());

			if (client->Credits())Object(writer, client->Credits(), index + 1, client);	//TODO: !!!Object for CClientCredits
			else {
				Key(_T("credit")); String(_T("null"));

			}

			/*//先全部注释掉吧
			Key(_T("Client")); String(_T("NotSupporttedYet"));
			Key(_T("isEd2kClient")); Bool(client->IsEd2kClient());
			Key(_T("checkHandshakeFinished")); Bool(client->CheckHandshakeFinished());
			Key(_T("userIDHybrid")); Int(client->GetUserIDHybrid());

			Key(_T("hasLowID")); Bool(client->HasLowID());
			Key(_T("connectIP")); Int(client->GetConnectIP());
			Key(_T("userPort")); Int(client->GetUserPort());

			Key(_T("serverIP")); Int(client->GetServerIP());
			Key(_T("serverPort")); Int(client->GetServerPort());
			Key(_T("userHash")); String(CString(client->GetUserHash()));
			Key(_T("hasValidHash")); Bool(client->HasValidHash());
			Key(_T("hashType")); Int(client->GetHashType());
			Key(_T("buddyID")); String(CString(client->GetBuddyID()));
			Key(_T("hasValidBuddyID")); Bool(client->HasValidBuddyID());
			Key(_T("buddyIP")); Int(client->GetBuddyIP());
			Key(_T("buddyPort")); Int(client->GetBuddyPort());
			//Object(writer,client->GetClientSoft());	//TODO: !!!Object for EClientSoftware

			Key(_T("isExtProtocolAvailable")); Bool(client->ExtProtocolAvailable());
			Key(_T("isSupportMultiPacket")); Bool(client->SupportMultiPacket());
			Key(_T("isSupportExtMultiPacket")); Bool(client->SupportExtMultiPacket());
			Key(_T("isSupportPeerCache")); Bool(client->SupportPeerCache());
			Key(_T("isSupportsLargeFiles")); Bool(client->SupportsLargeFiles());
			Key(_T("isSupportsFileIdentifiers")); Bool(client->SupportsFileIdentifiers());
			Key(_T("isEmuleClient")); Bool(client->IsEmuleClient());
			Key(_T("sourceExchange1Version")); Int(client->GetSourceExchange1Version());
			Key(_T("isSupportsSourceExchange2")); Bool(client->SupportsSourceExchange2());

			Key(_T("clientFilename")); String(client->GetClientFilename());
			Key(_T("uDPPort")); Int(client->GetUDPPort());
			Key(_T("uDPVersion")); Int(client->GetUDPVersion());
			Key(_T("isSupportsUDP")); Bool(client->SupportsUDP());
			Key(_T("kadPort")); Int(client->GetKadPort());
			Key(_T("extendedRequestsVersion")); Int(client->GetExtendedRequestsVersion());
			//Object(writer, client->GetConnectingState());//TODO: !!!WriterObject for EConnectingState
			Key(_T("lastSrcReqTime")); Int(client->GetLastSrcReqTime());
			Key(_T("lastSrcAnswerTime")); Int(client->GetLastSrcAnswerTime());
			Key(_T("lastAskedForSources")); Int(client->GetLastAskedForSources());
			Key(_T("friendSlot")); Bool(client->GetFriendSlot());
			Key(_T("isFriend")); Bool(client->IsFriend());

			//Object(writer, client->GetFriend(),index+1);//警告：可能产生无穷递归

			Key(_T("sentCancelTransfer")); Bool(client->GetSentCancelTransfer());
			Key(_T("kadVersion")); Int(client->GetKadVersion());
			Key(_T("isSendBuddyPingPong")); Bool(client->SendBuddyPingPong());
			Key(_T("isAllowIncomeingBuddyPingPong")); Bool(client->AllowIncomeingBuddyPingPong());
			Key(_T("secureIdentState")); Int(client->GetSecureIdentState());
			Key(_T("infoPacketsReceived")); Bool(client->GetInfoPacketsReceived());
			Key(_T("isSupportPreview")); Bool(client->GetPreviewSupport());
			Key(_T("isSupportViewSharedFiles")); Bool(client->GetViewSharedFilesSupport());
			Key(_T("isRequestsCryptLayer")); Bool(client->RequestsCryptLayer());
			Key(_T("isRequiresCryptLayer")); Bool(client->RequiresCryptLayer());
			Key(_T("isSupportsDirectUDPCallback")); Bool(client->SupportsDirectUDPCallback());
			Key(_T("isObfuscatedConnectionEstablished")); Bool(client->IsObfuscatedConnectionEstablished());
			Key(_T("isShouldReceiveCryptUDPPackets")); Bool(client->ShouldReceiveCryptUDPPackets());
			WriterObject(writer, client->GetUploadState());	//TODO: WriterObject for EUploadState
			Key(_T("waitStartTime")); Int64(client->GetWaitStartTime());
			Key(_T("waitTime")); Int(client->GetWaitTime());
			Key(_T("isDownloading")); Bool(client->IsDownloading());
			Key(_T("hasBlocks")); Bool(client->HasBlocks());
			Key(_T("numberOfRequestedBlocksInQueue")); Uint(client->GetNumberOfRequestedBlocksInQueue());
			Key(_T("upStartTimeDelay")); Uint(client->GetUpStartTimeDelay());
			Key(_T("uploadFileID")); String(CString(client->GetUploadFileID()));
			Key(_T("sendBlockData")); Uint(client->SendBlockData());
			Key(_T("askedCount")); Uint(client->GetAskedCount());
			Key(_T("lastUpRequest")); Uint(client->GetLastUpRequest());
			Key(_T("hasCollectionUploadSlot")); Bool(client->HasCollectionUploadSlot());
			Key(_T("sessionUp")); Uint(client->GetSessionUp());
			Key(_T("sessionPayloadDown")); Uint(client->GetSessionPayloadDown());
			Key(_T("queueSessionPayloadUp")); Bool(client->GetQueueSessionPayloadUp());
			Key(_T("payloadInBuffer")); Bool(client->GetPayloadInBuffer());
			Key(_T("upPartCount")); Uint(client->GetUpPartCount());
			Key(_T("upPartStatus")); Uint(*(client->GetUpPartStatus()));
			Key(_T("combinedFilePrioAndCredit")); Double(client->GetCombinedFilePrioAndCredit());
			Key(_T("askedCountDown")); Int(client->GetAskedCountDown());
			//Object(writer,client->GetDownloadState());	//TODO: WriterObject for EDownloadState
			Key(_T("partStatus")); Uint(*(client->GetPartStatus()));
			Key(_T("partCount")); Uint(client->GetPartCount());
			Key(_T("remoteQueueRank")); Int(client->GetRemoteQueueRank());
			Key(_T("isRemoteQueueFull")); Bool(client->IsRemoteQueueFull());
			Key(_T("availablePartCount")); Int(client->GetAvailablePartCount());
			Key(_T("uDPPacketPending")); Int(client->UDPPacketPending());
			Key(_T("isSourceRequestAllowed")); Int(client->IsSourceRequestAllowed());
			Key(_T("isValidSource")); Int(client->IsValidSource());
			//WriterObject(client->GetSourceFrom());	//TODO: WriterObject for ESourceFrom
			Key(_T("upCompleteSourcesCount")); Int(client->GetUpCompleteSourcesCount());
			//WriterObject(writer,client->GetChatState());	//TODO:WriterObject for EChatState
			//WriterObject(writer,client->GetChatCaptchaState());	//TODO:WriterObject for EChatCaptchaState
			Key(_T("messagesReceived")); Int(client->GetMessagesReceived());
			Key(_T("messagesSent")); Int(client->GetMessagesSent());
			Key(_T("isSpammer")); Bool(client->IsSpammer());
			Key(_T("messageFiltered")); Bool(client->GetMessageFiltered());
			//WriterObject(writer,client->GetKadState());	//TODO: WriterObject for EKadState
			Key(_T("hasFileComment")); Bool(client->HasFileComment());
			Key(_T("fileComment")); String(client->GetFileComment());
			Key(_T("hasFileRating")); Bool(client->HasFileRating());
			Key(_T("reqFileAICHHash")); Object(writer, client->GetReqFileAICHHash());
			Key(_T("isSupportingAICH")); Bool(client->IsSupportingAICH());
			Key(_T("isAICHReqPending")); Bool(client->IsAICHReqPending());
			//WriterObject(writer,client->GetUnicodeSupport());	//TODO: WriterObject for EUtf8Str
			Key(_T("downloadStateDisplayString")); String(client->GetDownloadStateDisplayString());
			Key(_T("uploadStateDisplayString")); String(client->GetUploadStateDisplayString());
			//WriterObject(writer,client->credits);	//TODO: WriterObject for CClientCredits
			//WriterObject(writer,clienr->m_OtherRequests_list);
			//WriterObject(writer,clienr->m_OtherNoNeeded_list);	//TODO: WriterObject for CTypedPtrList<CPtrList, CPartFile*>
			Key(_T("lastPartAsked")); Int(client->m_lastPartAsked);
			Key(_T("addNextConnect")); Bool(client->m_bAddNextConnect);
			Key(_T("isDownloadingFromPeerCache")); Bool(client->IsDownloadingFromPeerCache());
			Key(_T("isUploadingToPeerCache")); Bool(client->IsUploadingToPeerCache());
			Key(_T("hasPeerCacheState")); Bool(client->HasPeerCacheState());
			Key(_T("httpSendState")); Int(client->GetHttpSendState());
			Key(_T("sendPeerCacheFileRequest")); Bool(client->SendPeerCacheFileRequest());
			Key(_T("onPeerCacheDownSocketTimeout")); Bool(client->OnPeerCacheDownSocketTimeout());
			Key(_T("upendsoon")); Bool(client->upendsoon);
			Key(_T("isDifferentPartBlock")); Bool(client->IsDifferentPartBlock());
			Key(_T("remainingBlocksToDownload")); Bool(client->GetRemainingBlocksToDownload());
			Key(_T("")); Bool(client->());
			//*/
			EndObject();
		}

	}

	void Object(WriterT& writer, CFriend* pail)//因为friend是关键字，这里用pail 
	{
		CUpDownClient* Client;
		Client = pail->GetLinkedClient();

		StartObject();
		Key(_T("userHash")); String(CString(pail->m_abyUserhash));//uchar[16]
		Key(_T("lastSeen")); Int64(pail->m_dwLastSeen);//有可能是64位时间
		Key(_T("lastUsedIP")); Int(pail->m_dwLastUsedIP);
		Key(_T("lastUsedPort")); Int(pail->m_nLastUsedPort);
		Key(_T("lastChatted")); Int(pail->m_dwLastChatted);
		Key(_T("name")); String(pail->m_strName);
		//TODO:讨论GetLinkedClient();的发送格式并实现	--准备进行
		Object(writer, Client);//TODO: Object for CUpDownClient
		//以及GetClientForChatSession();的功能及实现
		Key(_T("isTryToConnet")); Bool(pail->IsTryingToConnect());
		Key(_T("isFriendSlotted")); Bool(pail->GetFriendSlot());
		Key(_T("hasUserHash")); Bool(pail->HasUserhash());
		Key(_T("hasKadID")); Bool(pail->HasKadID());

		EndObject();
	}
	//似乎返回CFriend是完全没有必要的？返回CUpDownClient类就好了
	//里面也有isFriend方法，如果需要返回所有Friend，通过查询所有
	//isFriend()=Ture的Client就好


	void Object(WriterT& writer, CAbstractFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Key(_T("fileName")); String(file->GetFileName());
		Key(_T("fileType")); String(file->GetFileType());
		Key(_T("fileTypeDisplayName")); String(file->GetFileTypeDisplayStr());
		//Object(writer,file->GetFileIdentifier());	//TODO: Object for CFileIdentifier
		Key(_T("fileHash")); String(CString(file->GetFileHash()));
		Key(_T("hasHashSet")); Bool(file->HasNullHash());
		Key(_T("eD2kLink")); String(file->GetED2kLink());//without Hashset;HTMLTag;HostName;Source;dwSourceIP
		//Object(writer,file->GetFileSize());	//TODO: Object for EMFileSize
		Key(_T("isLargeFile")); Bool(file->IsLargeFile());
		Key(_T("isPartfile")); Bool(file->IsPartFile());
		Key(_T("hasComment")); Bool(file->HasComment());
		Key(_T("userRating")); Int(file->UserRating());
		Key(_T("hasUserRating")); Bool(file->HasRating());
		Key(_T("hasBadRating")); Bool(file->HasBadRating());
		Key(_T("fileComment")); String(file->GetFileComment());
		Key(_T("fileRating")); Int(file->GetFileRating());
		//Object(writer, file->getNotes());	//TODO:Object for CKadEntryPtrList
		Key(_T("isKadCommentSearchRunning")); Bool(file->IsKadCommentSearchRunning());
		Key(_T("isCompressible")); Bool(file->IsCompressible());
		if (!index)EndObject();
	}
	void Object(WriterT& writer, CShareableFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object(writer, (CAbstractFile*)file, index + 1);
		//Object(writer,file->GetVerifiedFileType());	//TODO:Object for EFileType
		Key(_T("isPartfile")); Bool(file->IsPartFile());
		Key(_T("path")); String(file->GetPath());
		Key(_T("sharedDirectory")); String(file->GetSharedDirectory());
		Key(_T("isShellLinked")); Bool(file->IsShellLinked());
		Key(_T("filePath")); String(file->GetFilePath());
		Key(_T("infoSummary")); String(file->GetInfoSummary());
		if (!index)EndObject();
	}
	void Object(WriterT& writer, CKnownFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object(writer, (CShareableFile*)file, index + 1);
		//Object(writer,file->GetUtcCFileDate);
		Key(_T("utcFileDate")); Int(file->GetUtcFileDate());
		Key(_T("isShouldPartiallyPurgeFile")); Bool(file->ShouldPartiallyPurgeFile());
		Key(_T("partCount")); Int(file->GetPartCount());
		Key(_T("eD2KPartCount")); Int(file->GetED2KPartCount());
		Key(_T("upPriority")); Int(file->GetUpPriority());
		Key(_T("upPriorityEx")); Int(file->GetUpPriorityEx());
		Key(_T("isAutoUpPriority")); Bool(file->IsAutoUpPriority());
		Key(_T("calculateUploadPriorityPercent")); Double(file->CalculateUploadPriorityPercent());
		Key(_T("wantedUpload")); Int64(file->GetWantedUpload());
		Key(_T("pushfaktor")); Double(file->pushfaktor);
		Key(_T("virtualUploadSources")); Int(file->m_nVirtualUploadSources);
		Key(_T("virtualSourceIndicator")); Int(file->GetVirtualSourceIndicator());
		Key(_T("virtualCompleteSourcesCount")); Int(file->m_nVirtualCompleteSourcesCount);
		Key(_T("getOnUploadqueue")); Int(file->GetOnUploadqueue());
		Key(_T("isPublishedED2K")); Bool(file->GetPublishedED2K());
		Key(_T("kadFileSearchID")); Int(file->GetKadFileSearchID());
		//Object(writer,file->GetKadKeywords())	//TODO: WriteObjects for Kademlia::WordList
		Key(_T("lastPublishTimeKadSrc")); Int(file->GetLastPublishTimeKadSrc());
		Key(_T("lastPublishBuddy")); Int(file->GetLastPublishBuddy());
		Key(_T("lastPublishTimeKadNotes")); Int(file->GetLastPublishTimeKadNotes());
		Key(_T("hasPublishSrc")); Bool(file->PublishSrc());
		Key(_T("hasPublishNotes")); Int(file->PublishNotes());
		Key(_T("metaDataVer")); Int(file->GetMetaDataVer());
		Key(_T("isMovie")); Bool(file->IsMovie());
		Key(_T("infoSummary")); String(file->GetInfoSummary());
		Key(_T("upPriorityDisplayString")); String(file->GetUpPriorityDisplayString());
		Key(_T("isAICHRecoverHashSetAvailable")); Bool(file->IsAICHRecoverHashSetAvailable());
		Key(_T("utcLastModified")); Int(file->m_tUtcLastModified);
		//Object(writer,file->statistic)	//TODO: WriteObjects for CStatisticFile
		Key(_T("completeSourcesTime")); Int(file->m_nCompleteSourcesTime);
		Key(_T("completeSourcesCount")); Int(file->m_nCompleteSourcesCount);
		Key(_T("completeSourcesCountLo")); Int(file->m_nCompleteSourcesCountLo);
		Key(_T("completeSourcesCountHi")); Int(file->m_nCompleteSourcesCountHi);
		//Object(writer,file->m_ClientUploadList)//TODO: WriterObject for CUpDownClientPtrList
		//Object(writer,file->m_AvailPartFrequency)//TODO: Object for CArray<uint16, uint16> 
		//Object(writer,file->m_pCollection)//TODO: Object for CCollection*
		Key(_T("isSR13_ImportParts")); Bool(file->SR13_ImportParts());
		Key(_T("startUploadTime")); Int(file->GetStartUploadTime());
		Key(_T("fileRatio")); Double(file->GetFileRatio());
		Key(_T("isPushSmallFile")); Bool(file->IsPushSmallFile());
		Key(_T("feedback")); String(file->GetFeedback());
		//Object(writer,file->m_PartSentCount)//TODO: Object for CArray<uint64> 
		Key(_T("hideOS")); Int(file->GetHideOS());
		Key(_T("selectiveChunk")); Int(file->GetSelectiveChunk());
		Key(_T("hideOSInWork")); Int(file->HideOSInWork());
		Key(_T("shareOnlyTheNeed")); Int(file->GetShareOnlyTheNeed());
		Key(_T("sotnInWork")); Int(file->SotnInWork());
		Key(_T("powerSharedMode")); Int(file->GetPowerSharedMode());
		Key(_T("ispowerShareAuthorized")); Bool(file->GetPowerShareAuthorized());
		Key(_T("ispowerShareAuto")); Bool(file->GetPowerShareAuto());
		Key(_T("powerShareLimit")); Int(file->GetPowerShareLimit());
		Key(_T("ispowerShareLimited")); Bool(file->GetPowerShareLimited());
		Key(_T("ispowerShared")); Bool(file->GetPowerShared());
		Key(_T("knownStyle")); Int(file->GetKnownStyle());
		Key(_T("psAmountLimit")); Int(file->GetPsAmountLimit());
		if (!index)EndObject();
	}
	void Object(WriterT& writer, CAICHHash* hash, unsigned char index = 0) {
		//StartObject();
		String(hash->GetString());
		//EndObject();
	}
	void Object(WriterT& writer, CAICHHashTree* hash, unsigned char index = 0) {
		//StartObject();
		Object(writer, &(hash->m_Hash));
		//EndObject();
	}
	void Object(WriterT& writer, CAICHRecoveryHashSet* hash, unsigned char index = 0) {
		//StartObject();
		Object(writer, &(hash->m_pHashTree));
		//EndObject();
	}
	void Object(WriterT& writer, CPartFile* file, unsigned char index = 0) {
		if (!index)StartObject();
		Object(writer, (CKnownFile*)file, index + 1);
		Key(_T("isPartFile")); Bool(file->IsPartFile());
		Key(_T("partMetFileName")); String(file->GetPartMetFileName());
		Key(_T("AICHHash")); Object(writer, file->GetAICHRecoveryHashSet());
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
		writer.Object(writer, cur);
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
		if(cur)writer.Object(writer, cur);
	}
	writer.EndArray();
	theApp.clientlist->FindHeadClient();
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
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("Not Supportt /shared Yet")));
	}else {
		pSocket->SendContent(CT2CA(JSONInit), CString(_T("null")));
	}
}
