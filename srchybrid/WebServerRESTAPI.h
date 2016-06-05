#pragma once
#include "WebServer.h"
class WebServerRESTAPI
{
private:
  static CString _GetServerList(ThreadData data, CString & param);
  static CString _GetClientList(ThreadData data, CString & param);
  static CString _GetSharedList(ThreadData data, CString & param);
  static CString _GetknownfList(ThreadData data, CString & param);
  static CString _Action(ThreadData data, CString & param,CString action=NULL);


public:
  WebServerRESTAPI();
  ~WebServerRESTAPI();
  static void Process(ThreadData data);
  
};

