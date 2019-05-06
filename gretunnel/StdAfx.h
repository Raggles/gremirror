/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  stdafx.h                                                */
/*                                                                       */
/* Abstract: include file for standard system include files,             */
/*  or project specific include files that are used frequently, but      */
/*  are changed infrequently                                             */
/*                                                                       */
/*************************************************************************/

#if !defined(AFX_STDAFX_H__8CD24513_169B_47A9_859B_9A99FF8266DA__INCLUDED_)
#define AFX_STDAFX_H__8CD24513_169B_47A9_859B_9A99FF8266DA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#endif // WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <Ws2tcpip.h>

#include "common.h"
#include "ndisapi.h"
#include "iphlp.h"

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__8CD24513_169B_47A9_859B_9A99FF8266DA__INCLUDED_)
