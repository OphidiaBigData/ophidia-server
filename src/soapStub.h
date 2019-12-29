/* soapStub.h
   Generated by gSOAP 2.8.96 for oph_wsdl.h

gSOAP XML Web services tools
Copyright (C) 2000-2018, Robert van Engelen, Genivia Inc. All Rights Reserved.
The soapcpp2 tool and its generated software are released under the GPL.
This program is released under the GPL with the additional exemption that
compiling, linking, and/or using OpenSSL is allowed.
--------------------------------------------------------------------------------
A commercial use license is available from Genivia Inc., contact@genivia.com
--------------------------------------------------------------------------------
*/


#ifndef soapStub_H
#define soapStub_H
#include "stdsoap2.h"
#if GSOAP_VERSION != 20896
# error "GSOAP VERSION 20896 MISMATCH IN GENERATED CODE VERSUS LIBRARY CODE: PLEASE REINSTALL PACKAGE"
#endif


/******************************************************************************\
 *                                                                            *
 * Types with Custom Serializers                                              *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Structs and Unions                                                         *
 *                                                                            *
\******************************************************************************/

struct oph__ophResponse;	/* oph_wsdl.h:72 */
struct oph__ophExecuteMain;	/* oph_wsdl.h:77 */
struct oph__oph_notifyResponse;	/* oph_wsdl.h:101 */
struct oph__oph_notify;	/* oph_wsdl.h:101 */

/* oph_wsdl.h:72 */
#ifndef SOAP_TYPE_oph__ophResponse
#define SOAP_TYPE_oph__ophResponse (43)
/* complex XML schema type 'oph:ophResponse': */
struct oph__ophResponse {
        /** Optional element 'jobid' of XML schema type 'xsd:string' */
        char *jobid;
        /** Optional element 'response' of XML schema type 'xsd:string' */
        char *response;
        /** Required element 'error' of XML schema type 'xsd:int' */
        long error;
};
#endif

/* oph_wsdl.h:77 */
#ifndef SOAP_TYPE_oph__ophExecuteMain
#define SOAP_TYPE_oph__ophExecuteMain (46)
/* complex XML schema type 'oph:ophExecuteMain': */
struct oph__ophExecuteMain {
        /** Optional element 'ophExecuteMainRequest' of XML schema type 'xsd:string' */
        char *ophExecuteMainRequest;
};
#endif

/* oph_wsdl.h:101 */
#ifndef SOAP_TYPE_oph__oph_notifyResponse
#define SOAP_TYPE_oph__oph_notifyResponse (49)
/* complex XML schema type 'oph:oph-notifyResponse': */
struct oph__oph_notifyResponse {
        /** Optional element 'oph-notify-response' of XML schema type 'xsd:int' */
        long *oph_notify_response;
};
#endif

/* oph_wsdl.h:101 */
#ifndef SOAP_TYPE_oph__oph_notify
#define SOAP_TYPE_oph__oph_notify (50)
/* complex XML schema type 'oph:oph-notify': */
struct oph__oph_notify {
        /** Optional element 'oph-notify-data' of XML schema type 'xsd:string' */
        char *oph_notify_data;
        /** Optional element 'oph-notify-json' of XML schema type 'xsd:string' */
        char *oph_notify_json;
};
#endif

/* oph_wsdl.h:102 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (51)
/* SOAP_ENV__Header: */
struct SOAP_ENV__Header {
#ifdef WITH_NOEMPTYSTRUCT
	char dummy;	/* empty struct is a GNU extension */
#endif
};
#endif
#endif

/* oph_wsdl.h:102 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (52)
/* Type SOAP_ENV__Code is a recursive data type, (in)directly referencing itself through its (base or derived class) members */
/* SOAP_ENV__Code: */
struct SOAP_ENV__Code {
        /** Optional element 'SOAP-ENV:Value' of XML schema type 'xsd:QName' */
        char *SOAP_ENV__Value;
        /** Optional element 'SOAP-ENV:Subcode' of XML schema type 'SOAP-ENV:Code' */
        struct SOAP_ENV__Code *SOAP_ENV__Subcode;
};
#endif
#endif

/* oph_wsdl.h:102 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (54)
/* SOAP_ENV__Detail: */
struct SOAP_ENV__Detail {
        char *__any;
        /** Any type of element 'fault' assigned to fault with its SOAP_TYPE_<typename> assigned to __type */
        /** Do not create a cyclic data structure through this member unless SOAP encoding or SOAP_XML_GRAPH are used for id-ref serialization */
        int __type;
        void *fault;
};
#endif
#endif

/* oph_wsdl.h:102 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (57)
/* SOAP_ENV__Reason: */
struct SOAP_ENV__Reason {
        /** Optional element 'SOAP-ENV:Text' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Text;
};
#endif
#endif

/* oph_wsdl.h:102 */
#ifndef WITH_NOGLOBAL
#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (58)
/* SOAP_ENV__Fault: */
struct SOAP_ENV__Fault {
        /** Optional element 'faultcode' of XML schema type 'xsd:QName' */
        char *faultcode;
        /** Optional element 'faultstring' of XML schema type 'xsd:string' */
        char *faultstring;
        /** Optional element 'faultactor' of XML schema type 'xsd:string' */
        char *faultactor;
        /** Optional element 'detail' of XML schema type 'SOAP-ENV:Detail' */
        struct SOAP_ENV__Detail *detail;
        /** Optional element 'SOAP-ENV:Code' of XML schema type 'SOAP-ENV:Code' */
        struct SOAP_ENV__Code *SOAP_ENV__Code;
        /** Optional element 'SOAP-ENV:Reason' of XML schema type 'SOAP-ENV:Reason' */
        struct SOAP_ENV__Reason *SOAP_ENV__Reason;
        /** Optional element 'SOAP-ENV:Node' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Node;
        /** Optional element 'SOAP-ENV:Role' of XML schema type 'xsd:string' */
        char *SOAP_ENV__Role;
        /** Optional element 'SOAP-ENV:Detail' of XML schema type 'SOAP-ENV:Detail' */
        struct SOAP_ENV__Detail *SOAP_ENV__Detail;
};
#endif
#endif

/******************************************************************************\
 *                                                                            *
 * Typedefs                                                                   *
 *                                                                            *
\******************************************************************************/


/* (built-in):0 */
#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (5)
typedef char *_XML;
#endif

/* (built-in):0 */
#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (6)
typedef char *_QName;
#endif

/* oph_wsdl.h:21 */
#ifndef SOAP_TYPE_xsd__anyURI
#define SOAP_TYPE_xsd__anyURI (7)
typedef char *xsd__anyURI;
#endif

/* oph_wsdl.h:22 */
#ifndef SOAP_TYPE_xsd__boolean
#define SOAP_TYPE_xsd__boolean (8)
typedef char xsd__boolean;
#endif

/* oph_wsdl.h:23 */
#ifndef SOAP_TYPE_xsd__date
#define SOAP_TYPE_xsd__date (9)
typedef char *xsd__date;
#endif

/* oph_wsdl.h:24 */
#ifndef SOAP_TYPE_xsd__dateTime
#define SOAP_TYPE_xsd__dateTime (11)
typedef time_t xsd__dateTime;
#endif

/* oph_wsdl.h:25 */
#ifndef SOAP_TYPE_xsd__double
#define SOAP_TYPE_xsd__double (13)
typedef double xsd__double;
#endif

/* oph_wsdl.h:26 */
#ifndef SOAP_TYPE_xsd__duration
#define SOAP_TYPE_xsd__duration (14)
typedef char *xsd__duration;
#endif

/* oph_wsdl.h:27 */
#ifndef SOAP_TYPE_xsd__float
#define SOAP_TYPE_xsd__float (16)
typedef float xsd__float;
#endif

/* oph_wsdl.h:28 */
#ifndef SOAP_TYPE_xsd__time
#define SOAP_TYPE_xsd__time (17)
typedef char *xsd__time;
#endif

/* oph_wsdl.h:29 */
#ifndef SOAP_TYPE_xsd__decimal
#define SOAP_TYPE_xsd__decimal (18)
typedef char *xsd__decimal;
#endif

/* oph_wsdl.h:30 */
#ifndef SOAP_TYPE_xsd__integer
#define SOAP_TYPE_xsd__integer (19)
typedef char *xsd__integer;
#endif

/* oph_wsdl.h:31 */
#ifndef SOAP_TYPE_xsd__long
#define SOAP_TYPE_xsd__long (21)
typedef LONG64 xsd__long;
#endif

/* oph_wsdl.h:32 */
#ifndef SOAP_TYPE_xsd__int
#define SOAP_TYPE_xsd__int (23)
typedef long xsd__int;
#endif

/* oph_wsdl.h:33 */
#ifndef SOAP_TYPE_xsd__short
#define SOAP_TYPE_xsd__short (25)
typedef short xsd__short;
#endif

/* oph_wsdl.h:34 */
#ifndef SOAP_TYPE_xsd__byte
#define SOAP_TYPE_xsd__byte (26)
typedef char xsd__byte;
#endif

/* oph_wsdl.h:35 */
#ifndef SOAP_TYPE_xsd__nonPositiveInteger
#define SOAP_TYPE_xsd__nonPositiveInteger (27)
typedef char *xsd__nonPositiveInteger;
#endif

/* oph_wsdl.h:36 */
#ifndef SOAP_TYPE_xsd__negativeInteger
#define SOAP_TYPE_xsd__negativeInteger (28)
typedef char *xsd__negativeInteger;
#endif

/* oph_wsdl.h:37 */
#ifndef SOAP_TYPE_xsd__nonNegativeInteger
#define SOAP_TYPE_xsd__nonNegativeInteger (29)
typedef char *xsd__nonNegativeInteger;
#endif

/* oph_wsdl.h:38 */
#ifndef SOAP_TYPE_xsd__positiveInteger
#define SOAP_TYPE_xsd__positiveInteger (30)
typedef char *xsd__positiveInteger;
#endif

/* oph_wsdl.h:39 */
#ifndef SOAP_TYPE_xsd__unsignedLong
#define SOAP_TYPE_xsd__unsignedLong (32)
typedef ULONG64 xsd__unsignedLong;
#endif

/* oph_wsdl.h:40 */
#ifndef SOAP_TYPE_xsd__unsignedInt
#define SOAP_TYPE_xsd__unsignedInt (35)
typedef unsigned long xsd__unsignedInt;
#endif

/* oph_wsdl.h:41 */
#ifndef SOAP_TYPE_xsd__unsignedShort
#define SOAP_TYPE_xsd__unsignedShort (37)
typedef unsigned short xsd__unsignedShort;
#endif

/* oph_wsdl.h:42 */
#ifndef SOAP_TYPE_xsd__unsignedByte
#define SOAP_TYPE_xsd__unsignedByte (39)
typedef unsigned char xsd__unsignedByte;
#endif

/* oph_wsdl.h:43 */
#ifndef SOAP_TYPE_xsd__string
#define SOAP_TYPE_xsd__string (40)
typedef char *xsd__string;
#endif

/* oph_wsdl.h:44 */
#ifndef SOAP_TYPE_xsd__normalizedString
#define SOAP_TYPE_xsd__normalizedString (41)
typedef char *xsd__normalizedString;
#endif

/* oph_wsdl.h:45 */
#ifndef SOAP_TYPE_xsd__token
#define SOAP_TYPE_xsd__token (42)
typedef char *xsd__token;
#endif

/******************************************************************************\
 *                                                                            *
 * Serializable Types                                                         *
 *                                                                            *
\******************************************************************************/


/* xsd__byte has binding name 'xsd__byte' for type 'xsd:byte' */
#ifndef SOAP_TYPE_xsd__byte
#define SOAP_TYPE_xsd__byte (26)
#endif

/* xsd__boolean has binding name 'xsd__boolean' for type 'xsd:boolean' */
#ifndef SOAP_TYPE_xsd__boolean
#define SOAP_TYPE_xsd__boolean (8)
#endif

/* char has binding name 'byte' for type 'xsd:byte' */
#ifndef SOAP_TYPE_byte
#define SOAP_TYPE_byte (3)
#endif

/* xsd__short has binding name 'xsd__short' for type 'xsd:short' */
#ifndef SOAP_TYPE_xsd__short
#define SOAP_TYPE_xsd__short (25)
#endif

/* short has binding name 'short' for type 'xsd:short' */
#ifndef SOAP_TYPE_short
#define SOAP_TYPE_short (24)
#endif

/* int has binding name 'int' for type 'xsd:int' */
#ifndef SOAP_TYPE_int
#define SOAP_TYPE_int (1)
#endif

/* xsd__int has binding name 'xsd__int' for type 'xsd:int' */
#ifndef SOAP_TYPE_xsd__int
#define SOAP_TYPE_xsd__int (23)
#endif

/* long has binding name 'long' for type 'xsd:long' */
#ifndef SOAP_TYPE_long
#define SOAP_TYPE_long (22)
#endif

/* xsd__long has binding name 'xsd__long' for type 'xsd:long' */
#ifndef SOAP_TYPE_xsd__long
#define SOAP_TYPE_xsd__long (21)
#endif

/* LONG64 has binding name 'LONG64' for type 'xsd:long' */
#ifndef SOAP_TYPE_LONG64
#define SOAP_TYPE_LONG64 (20)
#endif

/* xsd__float has binding name 'xsd__float' for type 'xsd:float' */
#ifndef SOAP_TYPE_xsd__float
#define SOAP_TYPE_xsd__float (16)
#endif

/* float has binding name 'float' for type 'xsd:float' */
#ifndef SOAP_TYPE_float
#define SOAP_TYPE_float (15)
#endif

/* xsd__double has binding name 'xsd__double' for type 'xsd:double' */
#ifndef SOAP_TYPE_xsd__double
#define SOAP_TYPE_xsd__double (13)
#endif

/* double has binding name 'double' for type 'xsd:double' */
#ifndef SOAP_TYPE_double
#define SOAP_TYPE_double (12)
#endif

/* xsd__unsignedByte has binding name 'xsd__unsignedByte' for type 'xsd:unsignedByte' */
#ifndef SOAP_TYPE_xsd__unsignedByte
#define SOAP_TYPE_xsd__unsignedByte (39)
#endif

/* unsigned char has binding name 'unsignedByte' for type 'xsd:unsignedByte' */
#ifndef SOAP_TYPE_unsignedByte
#define SOAP_TYPE_unsignedByte (38)
#endif

/* xsd__unsignedShort has binding name 'xsd__unsignedShort' for type 'xsd:unsignedShort' */
#ifndef SOAP_TYPE_xsd__unsignedShort
#define SOAP_TYPE_xsd__unsignedShort (37)
#endif

/* unsigned short has binding name 'unsignedShort' for type 'xsd:unsignedShort' */
#ifndef SOAP_TYPE_unsignedShort
#define SOAP_TYPE_unsignedShort (36)
#endif

/* unsigned int has binding name 'unsignedInt' for type 'xsd:unsignedInt' */
#ifndef SOAP_TYPE_unsignedInt
#define SOAP_TYPE_unsignedInt (33)
#endif

/* xsd__unsignedInt has binding name 'xsd__unsignedInt' for type 'xsd:unsignedInt' */
#ifndef SOAP_TYPE_xsd__unsignedInt
#define SOAP_TYPE_xsd__unsignedInt (35)
#endif

/* unsigned long has binding name 'unsignedLong' for type 'xsd:unsignedLong' */
#ifndef SOAP_TYPE_unsignedLong
#define SOAP_TYPE_unsignedLong (34)
#endif

/* xsd__unsignedLong has binding name 'xsd__unsignedLong' for type 'xsd:unsignedLong' */
#ifndef SOAP_TYPE_xsd__unsignedLong
#define SOAP_TYPE_xsd__unsignedLong (32)
#endif

/* ULONG64 has binding name 'ULONG64' for type 'xsd:unsignedLong' */
#ifndef SOAP_TYPE_ULONG64
#define SOAP_TYPE_ULONG64 (31)
#endif

/* xsd__dateTime has binding name 'xsd__dateTime' for type 'xsd:dateTime' */
#ifndef SOAP_TYPE_xsd__dateTime
#define SOAP_TYPE_xsd__dateTime (11)
#endif

/* time_t has binding name 'dateTime' for type 'xsd:dateTime' */
#ifndef SOAP_TYPE_dateTime
#define SOAP_TYPE_dateTime (10)
#endif

/* struct SOAP_ENV__Fault has binding name 'SOAP_ENV__Fault' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Fault
#define SOAP_TYPE_SOAP_ENV__Fault (58)
#endif

/* struct SOAP_ENV__Reason has binding name 'SOAP_ENV__Reason' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Reason
#define SOAP_TYPE_SOAP_ENV__Reason (57)
#endif

/* struct SOAP_ENV__Detail has binding name 'SOAP_ENV__Detail' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Detail
#define SOAP_TYPE_SOAP_ENV__Detail (54)
#endif

/* struct SOAP_ENV__Code has binding name 'SOAP_ENV__Code' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Code
#define SOAP_TYPE_SOAP_ENV__Code (52)
#endif

/* struct SOAP_ENV__Header has binding name 'SOAP_ENV__Header' for type '' */
#ifndef SOAP_TYPE_SOAP_ENV__Header
#define SOAP_TYPE_SOAP_ENV__Header (51)
#endif

/* struct oph__oph_notify has binding name 'oph__oph_notify' for type 'oph:oph-notify' */
#ifndef SOAP_TYPE_oph__oph_notify
#define SOAP_TYPE_oph__oph_notify (50)
#endif

/* struct oph__oph_notifyResponse has binding name 'oph__oph_notifyResponse' for type 'oph:oph-notifyResponse' */
#ifndef SOAP_TYPE_oph__oph_notifyResponse
#define SOAP_TYPE_oph__oph_notifyResponse (49)
#endif

/* struct oph__ophExecuteMain has binding name 'oph__ophExecuteMain' for type 'oph:ophExecuteMain' */
#ifndef SOAP_TYPE_oph__ophExecuteMain
#define SOAP_TYPE_oph__ophExecuteMain (46)
#endif

/* struct oph__ophResponse has binding name 'oph__ophResponse' for type 'oph:ophResponse' */
#ifndef SOAP_TYPE_oph__ophResponse
#define SOAP_TYPE_oph__ophResponse (43)
#endif

/* struct SOAP_ENV__Reason * has binding name 'PointerToSOAP_ENV__Reason' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Reason
#define SOAP_TYPE_PointerToSOAP_ENV__Reason (60)
#endif

/* struct SOAP_ENV__Detail * has binding name 'PointerToSOAP_ENV__Detail' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Detail
#define SOAP_TYPE_PointerToSOAP_ENV__Detail (59)
#endif

/* struct SOAP_ENV__Code * has binding name 'PointerToSOAP_ENV__Code' for type '' */
#ifndef SOAP_TYPE_PointerToSOAP_ENV__Code
#define SOAP_TYPE_PointerToSOAP_ENV__Code (53)
#endif

/* long * has binding name 'PointerToxsd__int' for type 'xsd:int' */
#ifndef SOAP_TYPE_PointerToxsd__int
#define SOAP_TYPE_PointerToxsd__int (47)
#endif

/* struct oph__ophResponse * has binding name 'PointerTooph__ophResponse' for type 'oph:ophResponse' */
#ifndef SOAP_TYPE_PointerTooph__ophResponse
#define SOAP_TYPE_PointerTooph__ophResponse (44)
#endif

/* xsd__token has binding name 'xsd__token' for type 'xsd:token' */
#ifndef SOAP_TYPE_xsd__token
#define SOAP_TYPE_xsd__token (42)
#endif

/* xsd__normalizedString has binding name 'xsd__normalizedString' for type 'xsd:normalizedString' */
#ifndef SOAP_TYPE_xsd__normalizedString
#define SOAP_TYPE_xsd__normalizedString (41)
#endif

/* xsd__string has binding name 'xsd__string' for type 'xsd:string' */
#ifndef SOAP_TYPE_xsd__string
#define SOAP_TYPE_xsd__string (40)
#endif

/* xsd__positiveInteger has binding name 'xsd__positiveInteger' for type 'xsd:positiveInteger' */
#ifndef SOAP_TYPE_xsd__positiveInteger
#define SOAP_TYPE_xsd__positiveInteger (30)
#endif

/* xsd__nonNegativeInteger has binding name 'xsd__nonNegativeInteger' for type 'xsd:nonNegativeInteger' */
#ifndef SOAP_TYPE_xsd__nonNegativeInteger
#define SOAP_TYPE_xsd__nonNegativeInteger (29)
#endif

/* xsd__negativeInteger has binding name 'xsd__negativeInteger' for type 'xsd:negativeInteger' */
#ifndef SOAP_TYPE_xsd__negativeInteger
#define SOAP_TYPE_xsd__negativeInteger (28)
#endif

/* xsd__nonPositiveInteger has binding name 'xsd__nonPositiveInteger' for type 'xsd:nonPositiveInteger' */
#ifndef SOAP_TYPE_xsd__nonPositiveInteger
#define SOAP_TYPE_xsd__nonPositiveInteger (27)
#endif

/* xsd__integer has binding name 'xsd__integer' for type 'xsd:integer' */
#ifndef SOAP_TYPE_xsd__integer
#define SOAP_TYPE_xsd__integer (19)
#endif

/* xsd__decimal has binding name 'xsd__decimal' for type 'xsd:decimal' */
#ifndef SOAP_TYPE_xsd__decimal
#define SOAP_TYPE_xsd__decimal (18)
#endif

/* xsd__time has binding name 'xsd__time' for type 'xsd:time' */
#ifndef SOAP_TYPE_xsd__time
#define SOAP_TYPE_xsd__time (17)
#endif

/* xsd__duration has binding name 'xsd__duration' for type 'xsd:duration' */
#ifndef SOAP_TYPE_xsd__duration
#define SOAP_TYPE_xsd__duration (14)
#endif

/* xsd__date has binding name 'xsd__date' for type 'xsd:date' */
#ifndef SOAP_TYPE_xsd__date
#define SOAP_TYPE_xsd__date (9)
#endif

/* xsd__anyURI has binding name 'xsd__anyURI' for type 'xsd:anyURI' */
#ifndef SOAP_TYPE_xsd__anyURI
#define SOAP_TYPE_xsd__anyURI (7)
#endif

/* _QName has binding name '_QName' for type 'xsd:QName' */
#ifndef SOAP_TYPE__QName
#define SOAP_TYPE__QName (6)
#endif

/* _XML has binding name '_XML' for type '' */
#ifndef SOAP_TYPE__XML
#define SOAP_TYPE__XML (5)
#endif

/* char * has binding name 'string' for type 'xsd:string' */
#ifndef SOAP_TYPE_string
#define SOAP_TYPE_string (4)
#endif

/******************************************************************************\
 *                                                                            *
 * Externals                                                                  *
 *                                                                            *
\******************************************************************************/


/******************************************************************************\
 *                                                                            *
 * Client-Side Call Stub Functions                                            *
 *                                                                            *
\******************************************************************************/

    
    /** Web service synchronous operation 'soap_call_oph__ophExecuteMain' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call_oph__ophExecuteMain(struct soap *soap, const char *soap_endpoint, const char *soap_action, char *ophExecuteMainRequest, struct oph__ophResponse *ophExecuteMainResponse);
    /** Web service asynchronous operation 'soap_send_oph__ophExecuteMain' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send_oph__ophExecuteMain(struct soap *soap, const char *soap_endpoint, const char *soap_action, char *ophExecuteMainRequest);
    /** Web service asynchronous operation 'soap_recv_oph__ophExecuteMain' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv_oph__ophExecuteMain(struct soap *soap, struct oph__ophResponse *ophExecuteMainResponse);
    
    /** Web service synchronous operation 'soap_call_oph__oph_notify' to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_call_oph__oph_notify(struct soap *soap, const char *soap_endpoint, const char *soap_action, char *oph_notify_data, char *oph_notify_json, long *oph_notify_response);
    /** Web service asynchronous operation 'soap_send_oph__oph_notify' to send a request message to the specified endpoint and SOAP Action header, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_send_oph__oph_notify(struct soap *soap, const char *soap_endpoint, const char *soap_action, char *oph_notify_data, char *oph_notify_json);
    /** Web service asynchronous operation 'soap_recv_oph__oph_notify' to receive a response message from the connected endpoint, returns SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 soap_recv_oph__oph_notify(struct soap *soap, long *oph_notify_response);

/******************************************************************************\
 *                                                                            *
 * Server-Side Operations                                                     *
 *                                                                            *
\******************************************************************************/

    /** Web service operation 'oph__ophExecuteMain' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 oph__ophExecuteMain(struct soap*, char *ophExecuteMainRequest, struct oph__ophResponse *ophExecuteMainResponse);
    /** Web service operation 'oph__oph_notify' implementation, should return SOAP_OK or error code */
    SOAP_FMAC5 int SOAP_FMAC6 oph__oph_notify(struct soap*, char *oph_notify_data, char *oph_notify_json, long *oph_notify_response);

/******************************************************************************\
 *                                                                            *
 * Server-Side Skeletons to Invoke Service Operations                         *
 *                                                                            *
\******************************************************************************/

SOAP_FMAC5 int SOAP_FMAC6 soap_serve(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_request(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_oph__ophExecuteMain(struct soap*);

SOAP_FMAC5 int SOAP_FMAC6 soap_serve_oph__oph_notify(struct soap*);

#endif

/* End of soapStub.h */
