#pragma once
#include "WebServer.h"
class WebServerRESTAPI
{
private:
  static CString _GetServerList(ThreadData data, CString & param);

public:
  WebServerRESTAPI();
  ~WebServerRESTAPI();
  static void Process(ThreadData data);
  
};
