//    IPscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011-2020 Tim Chappell.
//
//    This file is part of IPscan.
//
//    IPscan is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with IPscan.  If not, see <http://www.gnu.org/licenses/>.

// ipscan_web.c version
// 0.01 - initial version
// 0.02 - improved HTML (transition to styles, general compliance)
// 0.03 - addition of ping functionality
// 0.04 - addition of indirect host support
// 0.05 - removal of empty HTML paragraph
// 0.06 - tidy up URIPATH and comparisons
// 0.07 - move to JSON array which supports port number and result
// 0.08 - remove unused parameters
// 0.09 - add http-equiv to force IE7 mimicry
// 0.10 - minor tweak to expected run-time for non-javascript browser message
// 0.11 - add service names to results table (modification to portlist, now structure)
// 0.12 - compress form vertically
// 0.13 - introduce UDP support
// 0.14 - support the optional removal of ping functionality
// 0.15 - support the optional removal of UDP functionality
// 0.16 - add special case support
// 0.17 - add end of test signalling
// 0.18 - lint improvements
// 0.19 - correct position of request.send()
// 0.20 - handle failure case when HTTP return-code is not 200
// 0.21 - lint check and improvements
// 0.22 - move final fetch earlier
// 0.23 - further javascript improvements
// 0.24 - remove commented-out javascript code
// 0.25 - move to single XML HHTP Request object
// 0.26 - add 'navigate away' handler to javascript version
// 0.27 - fix cut'n'paste error, spotted by coverity
// 0.28 - update copyright year, and ensure charset=iso-8859-1
// 0.29 - update copyright year
// 0.30 - add basic HTML5/CSS support for javascript binaries
// 0.31 - specify value if terms accepted
// 0.32 - update copyright year
// 0.33 - slight tweak to error reporting (myReadyState and myStatus)
// 0.34 - update copyright year
// 0.35 - extern udpated
// 0.36 - semmle re-entrant time functions added
// 0.37 - javascript updates (removal of eval) and tidy
// 0.38 - add log for time_r failures
// 0.39 - update copyright year

#include "ipscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <strings.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <inttypes.h>

// Logging with syslog requires additional include
#if (LOGMODE == 1)
#include <syslog.h>
#endif

void create_html_common_header(void)
{
	printf("%s%c%c\n","content-type:text/html;charset=iso-8859-1",13,10);
	printf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
	printf("<html lang=\"en\">\n");
	printf("<head>\n");
	// Force later IE browsers to mimic IE7 as detailed in http://msdn.microsoft.com/library/cc288325.aspx
	printf("<meta http-equiv=\"x-ua-compatible\" content=\"ie=emulateie7\">\n");
	printf("<meta http-equiv=\"content-type\" content=\"text/html;charset=iso-8859-1\">\n");
	printf("<meta name=\"author\" content=\"tim chappell\">\n");
	printf("<meta http-equiv=\"cache-control\" content=\"no-store, no-cache, must-revalidate, max-age=0\">\n");
	printf("<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
	#ifdef IPSCAN_ICON_ENABLED
	printf("<link rel=\"icon\" type=\"%s\" href=\"%s\">\n", IPSCAN_ICON_TYPE, IPSCAN_ICON_HREF);
	#endif
	printf("<meta name=\"robots\" content=\"noindex, nofollow\">\n");
	printf("<meta name=\"copyright\" content=\"copyright (c) 2011-2020 tim chappell.\">\n");
}

#ifdef IPSCAN_HTML5_ENABLED
void create_html5_common_header(void)
{
	printf("%s%c%c\n","content-type:text/html;charset=utf-8",13,10);
	printf("<!DOCTYPE html>\n");
	printf("<html lang=\"en-gb\">\n");
	printf("<head>\n");
	printf("<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n");
	printf("<meta name=\"author\" content=\"tim chappell\">\n");
	printf("<meta http-equiv=\"cache-control\" content=\"no-store, no-cache, must-revalidate, max-age=0\">\n");
	printf("<meta http-equiv=\"pragma\" content=\"no-cache\">\n");
	#ifdef IPSCAN_ICON_ENABLED
	printf("<link rel=\"icon\" type=\"%s\" href=\"%s\"/>\n", IPSCAN_ICON_TYPE, IPSCAN_ICON_HREF);
	#endif
	printf("<meta name=\"robots\" content=\"noindex, nofollow\"/>\n");
	printf("<meta name=\"copyright\" content=\"copyright (c) 2011-2020 tim chappell.\">\n");
	printf("<style>\n");
	printf("body {\n");
	printf("background-color: #f0f0f2;\n");
	printf("margin: 0;\n");
	printf("padding: 0;\n");
	printf("font-family: \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n");
	printf("}\n");
	printf("div {\n");
	printf("width: %dpx;\n", IPSCAN_BODYDIV_WIDTH);
	printf("margin: 5em auto;\n");
	printf("padding: 50px;\n");
	printf("background-color: #fff;\n");
	printf("border-radius: 1em;\n");
	printf("}\n");
	printf("table {\n");
	printf("border: 1px solid black;\n");
	printf("font-family: \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n");
	printf("border-collapse: collapse;\n");
	printf("width: 100%%;\n");
	printf("}\n");
	printf("td, th {\n");
	printf("border: 1px solid black;\n");
	printf("padding: 8px;\n");
	printf("}\n");
	printf("tr:nth-child(even) {\n");
	printf("background-color: #dddddd;\n");
	printf("}\n");
	printf("</style>\n");

}
#endif

void create_json_header(void)
{
	printf("%s%c%c\n","Content-type:application/json;charset=utf-8",13,10);
}

void create_html_header(uint64_t session, time_t timestamp, uint16_t numports, uint16_t numudpports, char * reconquery)
{
	uint16_t i;

	HTML_HEADER();

	printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
	printf("<script type = \"text/javascript\" language=\"javascript\">\n");
	printf("<!--  to hide script contents from old browsers\n");
	printf("var myInterval = 0, myBlink = 0, myHTTPTimeout, myXmlHttpReqObj, fetches = 0, lastUpdate = 0;\n");

	// create a prefilled array containing the potential states returned for each port
	printf("var retVals = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (0 == i) printf("%d",resultsstruct[i].returnval); else printf(", %d",resultsstruct[i].returnval);
	}
	printf("];\n");

	// create a prefilled array containing the text label (shorthand) describing each of the potential states returned for each port
	printf("var labels = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (0 == i) printf("\"%s\"",resultsstruct[i].label); else printf(", \"%s\"",resultsstruct[i].label);
	}
	printf("];\n");

	// create a prefilled array containing the colour to be applied to each of the potential states returned for each port
	printf("var colours = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (0 == i) printf("\"%s\"",resultsstruct[i].colour); else printf(", \"%s\"",resultsstruct[i].colour);
	}
	printf("];\n");

	// create an HTTP object which copes with each of the various browser vagaries
	printf("function makeHttpObject() ");
	printf("{");
	printf(" try {return new XMLHttpRequest(); }");
	printf(" catch (error) {}");
	printf(" try {return new ActiveXObject(\"Msxml2.XMLHTTP\"); }");
	printf(" catch (error) {}");
	printf(" try {return new ActiveXObject(\"Microsoft.XMLHTTP\"); }");
	printf(" catch (error) {}");
	printf(" throw new Error(\"Could not create HTTP request object.\"); ");
	printf("}\n");

	// function to "blink" the test running state during test execution
	printf("function blink() ");
	printf("{");
	printf(" if (document.getElementById(\"scanstate\").style.color == \"red\")");
	printf(" {");
	printf("  document.getElementById(\"scanstate\").style.color = \"black\";");
	printf(" }");
	printf(" else");
	printf(" {");
	printf(" document.getElementById(\"scanstate\").style.color = \"red\";");
	printf(" } ");
	printf("}\n");

	// function to report HTTP transfer timed out
	printf("function HTTPTimedOut()");
	printf(" {");
	printf(" var badfinishURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=%d\";", session, (uint32_t)timestamp, reconquery, IPSCAN_HTTPTIMEOUT_COMPLETION);
	printf(" clearTimeout(myHTTPTimeout);");
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", badfinishURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" }\n");

	// function to report test never finished
	printf("function HTTPUnfinished()");
	printf(" {");
	printf(" var badfinishURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=%d\";", session, (uint32_t)timestamp, reconquery, IPSCAN_UNSUCCESSFUL_COMPLETION);
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", badfinishURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" }\n");

	// function to report test finished successfully
	printf("function HTTPFinished()");
	printf(" {");
	//If we get to here then we've managed to fetch all the results and the test is complete
	printf(" var finishURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=%d\";", session, (uint32_t)timestamp, reconquery, IPSCAN_SUCCESSFUL_COMPLETION);
	// Send indication that fetch is complete and results can be deleted.
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", finishURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" }\n");

	// function to report HTTP transfer completed with unexpected state
	printf("function HTTPUnexpected(myReadyState,myStatus)");
	printf(" {");
	printf(" var errorstring = \"STATUS:\" + myStatus + \"READYSTATE:\" + myReadyState;");
	printf(" var unexpectedURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=%d&string=\" + encodeURIComponent(errorstring);", session, (uint32_t)timestamp, reconquery, IPSCAN_UNEXPECTED_CHANGE);
	// HTTP GET completed, but with an unexpected HTTP status code (i.e. not 200 OK)
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", unexpectedURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" }\n");

	// function to report User chose to navigate away from the test, before completion
	printf("function HTTPNavAway()");
	printf(" {");
	printf(" var navAwayURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=%d\";", session, (uint32_t)timestamp, reconquery, IPSCAN_NAVIGATE_AWAY);
	printf(" clearTimeout(myHTTPTimeout);");
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", navAwayURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" }\n");

	// Page Exit Handler
	printf("var pageExitHandler = function(e)");
	printf(" {");
	// Include window.event in case the causative event wasn't passed in directly
	printf(" if (!e) var e = window.event;");
	printf(" var message = 'Do you wish to end the IPv6 port scan prematurely?';");
	printf(" HTTPNavAway();");
	// For legacy browsers
	printf(" if (e) { e.returnValue = message; }");
	// For modern browsers
	printf(" return message;");
	printf(" }\n");

	//
	// function to handle GET state change
	//
	printf("function myStateChange(request) ");
	printf("{");
	printf(" var i, j, psp, proto, special, port, result, host, textupdate, colourupdate, elemid, latestState = [];");
	printf(" if (request.readyState == 4 && request.status == 200)");
	printf(" {");
	printf(" clearTimeout(myHTTPTimeout);");

	// if response.length >0 and first character is '[' then
	// parse the response, assuming it is a valid update
	printf(" if (request.responseText.length > 0 && request.responseText[0]=='[')");
	printf(" {");
	printf(" latestState = JSON.parse(request.responseText);");
	printf(" };");

	printf(" if (latestState.length > 3)");
	printf(" {");
	#if (IPSCAN_INCLUDE_PING ==1)
	// if we've received a complete set of results for the ports under test then stop the periodic tasks
	// we expect (numudpports+PING+numports)*3+3 (final 3 are end of JSON array dummies) results
	printf(" if (latestState.length >= %d)", 3+((numudpports+1+numports)*3) );
	#else
	// if we've received a complete set of results for the ports under test then stop the periodic tasks
	// we expect (numudpports+numports)*3+3 (final 3 are end of JSON array dummies) results
	printf(" if (latestState.length >= %d)", 3+((numudpports+numports)*3) );
	#endif
	printf(" {");
	printf(" clearInterval(myInterval);");
	printf(" clearInterval(myBlink);");
	printf(" HTTPFinished();");
	printf(" }");

	//
	// go around the latest received state and update display as required
	//
	printf(" for (i = 0; i < (latestState.length - 3); i += 3) {");
	printf(" textupdate = \"%s\";", resultsstruct[PORTUNKNOWN].label);
	printf(" colourupdate = \"%s\";", resultsstruct[PORTUNKNOWN].colour);
	printf(" elemid = \"pingstate\";");
	// psp = protocol, special, port
	printf(" psp = latestState[i];");
	printf(" proto = ((psp >> %d) & %d);", IPSCAN_PROTO_SHIFT, IPSCAN_PROTO_MASK);
	printf(" special = ((psp >> %d) & %d);", IPSCAN_SPECIAL_SHIFT, IPSCAN_SPECIAL_MASK);
	printf(" port = ((psp >> %d) & %d);", IPSCAN_PORT_SHIFT, IPSCAN_PORT_MASK);
	printf(" result = latestState[i+1];");
	printf(" host = latestState[i+2];");

	printf(" if (proto == %d) { elemid = \"udpport\" + port; }", IPSCAN_PROTO_UDP);
	printf(" else if (proto == %d) { elemid = \"pingstate\"; }", IPSCAN_PROTO_ICMPV6);
	printf(" else { elemid = \"port\" + port; }");

	printf(" if (0 != special) { elemid += \":\" + special; }");

	printf(" for (j = 0; j < retVals.length; j += 1)");
	printf(" {");
	printf(" if (retVals[j] == (result & %d)) {", IPSCAN_INDIRECT_MASK);

	printf(" switch(proto) {");
	printf(" case %d:", IPSCAN_PROTO_ICMPV6); // ICMPv6
	printf(" if (result >= %d)", IPSCAN_INDIRECT_RESPONSE);
	printf(" { textupdate = \"INDIRECT-\" + labels[j] + \" (from \" + host + \")\"; } else { textupdate = labels[j]; }");
	printf(" break;");

	printf(" case %d:", IPSCAN_PROTO_UDP); // UDP
	printf(" if (result >= %d) {", IPSCAN_INDIRECT_RESPONSE);
	printf(" if (0 != special) { textupdate = \"Port \" + port + \"[\" + special + \"]\" + \" = INDIRECT-\" + labels[j] + \" (from \" + host + \")\"; } ");
	printf(" else { textupdate = \"Port \" + port + \" = INDIRECT-\" + labels[j] + \" (from \" + host + \")\"; }");
	printf(" } else {");
	printf(" if (0 != special) { textupdate = \"Port \" + port + \"[\" + special + \"]\" + \" = \" + labels[j]; } else { textupdate = \"Port \" + port + \" = \" + labels[j]; }");
	printf(" }");
	printf(" break;");

	printf(" default:"); // TCP
	printf(" if (0 != special) { textupdate = \"Port \" + port + \"[\" + special + \"]\" + labels[j]; } else { textupdate = \"Port \" + port + \" = \" + labels[j]; }");
	printf(" break;");

	printf(" }");

	// Colour setting
	printf(" colourupdate = colours[j];");
	printf(" }");
	printf(" }");

	// update the selected text on the page ....
	printf(" document.getElementById(elemid).innerHTML = textupdate;");
	printf(" document.getElementById(elemid).style.backgroundColor = colourupdate;");
	printf(" }"); // end of main for (i) loop

	#if (IPSCAN_INCLUDE_PING == 1)
	// if we have finished then update the page to reflect the fact
	printf(" if (latestState.length >= %d)",3+((numudpports+numports+1)*3) );
	#else
	// if we have finished then update the page to reflect the fact (no ping result in this case)
	printf(" if (latestState.length >= %d)",3+((numudpports+numports)*3) );
	#endif
	printf(" {");
	printf(" document.getElementById(\"scanstate\").innerHTML = \"COMPLETE.\";");
	printf(" document.getElementById(\"scanstate\").style.color = \"black\";");
	// Disable the Page Exit handler
	printf(" window.onbeforeunload = null;\n");
	printf(" }");

	printf(" }"); // end of main if (more than 3 elements in array)
	printf(" }"); // if (return code == 200)

	// The following piece of code is evaluated irrespective of the HTTP return code
	#if (IPSCAN_INCLUDE_PING ==1)
	// handle failure to complete the scan in the allocated number of updates (including ping result)
	printf(" else if (request.readyState == 4 && latestState.length < %d && lastUpdate == 1)",3+((numudpports+numports+1)*3));
	#else
	// handle failure to complete the scan in the allocated number of updates (no ping result)
	printf(" else if (request.readyState == 4 && latestState.length < %d && lastUpdate == 1)",3+((numudpports+numports)*3));
	#endif
	printf(" {");
	printf(" clearInterval(myBlink);");
	printf(" document.getElementById(\"scanstate\").innerHTML = \"FAILED.\";");
	printf(" document.getElementById(\"scanstate\").style.color = \"red\";");
	// Disable the Page Exit handler
	printf(" window.onbeforeunload = null;\n");
	printf(" HTTPUnexpected(request.readyState, request.status);");
	printf(" HTTPUnfinished();");
	printf(" }");
	printf(" }\n"); // end of myStateChange function()

	// the update() function schedules a GET from the server and then awaits its successful completion.
	printf("function update() ");
	printf("{ ");
	printf("fetches += 1; ");
	printf("var updateURL = \""URIPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=\" + fetches; ", session, (uint32_t)timestamp, reconquery);
	printf("if (fetches > %d) ",(int)( 8 + ((12 + (numudpports*UDPTIMEOUTSECS) + (numports*TIMEOUTSECS)) / JSONFETCHEVERY )) );
	printf("{");
	printf(" clearInterval(myInterval);");
	printf(" lastUpdate = 1; ");
	printf("}");
	printf(" if (myXmlHttpReqObj.readyState < 4) { myXmlHttpReqObj.abort(); }");
	printf(" myXmlHttpReqObj.open(\"GET\", updateURL, true);");
	// the myStateChange() function waits for the asynchronous HTTP 200 code to be received and then evaluates the returned JSON array.
	printf(" myXmlHttpReqObj.onreadystatechange = function(){myStateChange(myXmlHttpReqObj); };");
	printf(" myHTTPTimeout = setTimeout(function() {HTTPTimedOut(); }, %d);", ((JSONFETCHEVERY - 1) * 1000) );
	printf(" myXmlHttpReqObj.send(\"\");");
	// end of function update()
	printf("}\n");

	// startTimer() is really the initiation function. it sets the scanstate to RUNNING to give the user confidence that things are happening.
	// then the initial GET is performed to request that the server begins the scan.
	// finally the periodic call of update() is scheduled in order to retrieve and reflect the ongoing scan status.
	printf("function startTimer()");
	printf(" {");
	printf(" document.getElementById(\"scanstate\").innerHTML = \"RUNNING.\";");
	printf(" document.getElementById(\"scanstate\").style.color = \"black\";");
	// Install the page exit handler
	printf(" window.onbeforeunload = pageExitHandler;\n");
	printf(" myBlink = setInterval(function(){blink(); }, 1000);");
	printf(" var startURL = \""URIPATH"/"EXENAME"?beginscan=%d&session=%"PRIu64"&starttime=%"PRIu32"&%s\";", MAGICBEGIN, session, (uint32_t)timestamp, reconquery);
	printf(" myXmlHttpReqObj = makeHttpObject();");
	printf(" myXmlHttpReqObj.open(\"GET\", startURL, true);");
	printf(" myXmlHttpReqObj.send(\"\");");
	printf(" myInterval = setInterval(function(){update(); }, %d);", (JSONFETCHEVERY*1000) );
	printf(" }\n"); // end of function startTimer()

	printf("// end hiding contents from old browsers -->\n");
	printf("</script>\n");
	printf("</head>\n");
}


void create_results_key_table(char * hostname, time_t timestamp)
{
	int i;
	char tstring[64];
	struct tm timestampbdt; // broken dowm time
	struct tm * tsptr = NULL;
	tsptr = localtime_r(&timestamp, &timestampbdt);

	printf("<p style=\"font-weight:bold\">");
	if (NULL != tsptr)
	{
		if (strftime(tstring, sizeof(tstring),"%a,%%20%d%%20%b%%20%Y%%20%T%%20%z", &timestampbdt) != 0)
		{
			printf("Special protocol tests, signified by [x] after a port number, test for known protocol weaknesses. ");
			printf("Further details of these tests can be found at <a href=\"%s\">Special protocol tests.</a>\n", IPSCAN_SPECIALTESTS_URL);
			// Offer the opportunity for feedback and a link to the source
			printf("If you have any queries related to the results of this scan, or suggestions for improvement/additions to its' functionality");
			printf(" then please <a href=\"mailto:%s?subject=Feedback%%20on%%20IPv6%%20scanner&amp;body=host:%%20%s,%%20time:%%20%s\">email me.</a> ",\
					EMAILADDRESS, hostname, tstring );
		}
	}
	else
	{
		IPSCAN_LOG( LOGPREFIX "ipscan_web: ERROR: localtime_r() in create_results_key_table() returned NULL\n");
	}

	printf("The source code for this scanner is freely available at <a href=\"https://github.com/timsgit/ipscan\">github.</a></p>\n");

	printf("<table border=\"1\">\n");
	printf("<tr style=\"text-align:left\">\n");
	printf("<td width=\"25%%\" style=\"background-color:white\">REPORTED STATE</td><td width=\"75%%\" style=\"background-color:white\">MEANING</td>\n");
	printf("</tr>\n");

	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		printf("<tr style=\"text-align:left\">\n");
		printf("<td width=\"25%%\" style=\"background-color:%s\">%s</td><td width=\"75%%\" style=\"background-color:white\"> %s</td>\n",resultsstruct[i].colour,\
				resultsstruct[i].label, resultsstruct[i].description);
		printf("</tr>\n");
	}
	printf("</table>\n");
	// Only include if ping is supported
	#if (IPSCAN_INCLUDE_PING ==1)
	printf("<p>NOTE: Results in the ICMPv6 ECHO REQUEST test marked as INDIRECT indicate an ICMPv6 error response was received from another host (e.g. a router or firewall) rather");
	printf(" than the host under test. In this case the address of the responding host is also displayed.</p>\n");
	#endif
}

void create_html_body(char * hostname, time_t timestamp, uint16_t numports, uint16_t numudpports, struct portlist_struc *portlist, struct portlist_struc *udpportlist)
{
	uint16_t portindex;
	uint16_t port;
	uint8_t special;
	int position = 0;
	int last = 0;
	char starttime[32]; // ctime requires 26 chars
	char * stptr = NULL;
	stptr = ctime_r(&timestamp, starttime);

	printf("<body onload = \"startTimer()\">\n");

	printf("<noscript>\n<hr>\n");
	printf("<h3 style=\"color:red\">Your browser does not support Javascript, or else it is disabled.</h3>\n");
	printf("<p>An alternative version of this IPv6 TCP port scanner which does not use Javascript is available from ");
	printf("the following <a href=\"%s/%s\">link.</a></p>\n", URIPATH, EXETXTNAME);
	printf("<p>This alternative version does not support realtime in-browser updates and will take up to ");
	printf("%d seconds to return the results.</p>\n", (int)ESTIMATEDTIMETORUN );
	printf("<hr>\n");
	printf("</noscript>\n");

	printf("<div>\n");

	printf("<h3>IPv6 Port Scan Results for host %s</h3>\n", hostname);

	if (NULL == stptr)
	{
		IPSCAN_LOG( LOGPREFIX "ipscan_web: ERROR: ctime_r() in create_html_body() returned NULL\n");
	}

	printf("<p>Scan beginning at: %s, expected to take up to %d seconds ...</p>\n", starttime, (int)ESTIMATEDTIMETORUN );

	printf("<table border=\"1\">\n");
	// ongoing status ROW
	printf("<tr style=\"text-align: left\">\n");
	printf("<td width=\"50%%\">Scan status is : </td><td width=\"50%%\" style=\"font-weight: bold\" id=\"scanstate\">IDLE.</td>\n");
	printf("</tr>\n");
	// Only include the PING result row if necessary
	#if (IPSCAN_INCLUDE_PING ==1)
	printf("<tr style=\"font-weight: normal\">\n");
	printf("<td width=\"50%%\" title=\"IPv6 Ping\">ICMPv6 ECHO REQUEST returned : </td><td width=\"50%%\" style=\"background-color:%s\" id=\"pingstate\">%s</td>\n",resultsstruct[PORTUNKNOWN].colour,resultsstruct[PORTUNKNOWN].label);
	printf("</tr>\n");
	#endif
	printf("</table>\n");

	if (numudpports > 0)
	{
		printf("<p style=\"font-weight: bold\">Individual IPv6 UDP port scan results (hover for service names):</p>\n");
		// Start of UDP table
		printf("<table border=\"1\">\n");

		for (portindex= 0; portindex < numudpports ; portindex++)
		{
			port = udpportlist[portindex].port_num;
			special = udpportlist[portindex].special;
			last = (portindex == (numudpports-1)) ? 1 : 0 ;

			if (position ==0) printf("<tr style=\"text-align:center\">\n");
			if (0 != special)
			{
				printf("<td width=\"%d%%\" title=\"%s\" style=\"background-color:%s\" id=\"udpport%d:%d\">Port %d[%d] = %s</td>\n",COLUMNUDPPCT,udpportlist[portindex].port_desc, resultsstruct[PORTUNKNOWN].colour, \
						port, special, port, special, resultsstruct[PORTUNKNOWN].label );
			}
			else
			{
				printf("<td width=\"%d%%\" title=\"%s\" style=\"background-color:%s\" id=\"udpport%d\">Port %d = %s</td>\n",COLUMNUDPPCT,udpportlist[portindex].port_desc, resultsstruct[PORTUNKNOWN].colour, \
						port, port, resultsstruct[PORTUNKNOWN].label );
			}
			position++;
			if (position >= MAXUDPCOLS || last == 1) { printf("</tr>\n"); position=0; };
		}
		// end of table
		printf("</table>\n");
	}

	printf("<p style=\"font-weight: bold\">Individual IPv6 TCP port scan results (hover for service names):</p>\n");
	// Start of table
	printf("<table border=\"1\">\n");
	position = 0;

	for (portindex= 0; portindex < numports ; portindex++)
	{
		port = portlist[portindex].port_num;
		special = portlist[portindex].special;
		last = (portindex == (numports-1)) ? 1 : 0 ;

		if (position ==0) printf("<tr style=\"text-align:center\">\n");
		if (0 != special)
		{
			printf("<td width=\"%d%%\" title=\"%s\" style=\"background-color:%s\" id=\"port%d:%d\">Port %d[%d] = %s</td>\n",COLUMNPCT,portlist[portindex].port_desc, resultsstruct[PORTUNKNOWN].colour, \
					port, special, port, special, resultsstruct[PORTUNKNOWN].label );
		}
		else
		{
			printf("<td width=\"%d%%\" title=\"%s\" style=\"background-color:%s\" id=\"port%d\">Port %d = %s</td>\n",COLUMNPCT,portlist[portindex].port_desc, resultsstruct[PORTUNKNOWN].colour, \
					port, port, resultsstruct[PORTUNKNOWN].label );
		}
		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}

	// end of table
	printf("</table>\n");
	printf("<br>\n");

	// Create results key table
	create_results_key_table(hostname, timestamp);

	printf("</div>\n");

}

void create_html_body_end(void)
{
	printf("</body>\n");
	printf("</html>\n");
}

void create_html_form(uint16_t numports, uint16_t numudpports, struct portlist_struc *portlist, struct portlist_struc *udpportlist)
{
	int i;
	uint16_t port,portindex;
	uint8_t special;
	int position = 0;
	int last = 0;

	printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
	printf("</head>\n");
	printf("<body>\n");
	printf("<h3 style=\"color:red\">IPv6 Port Scanner by Tim Chappell</h3>\n");

	printf("<p>Please note that this test may take up to %d seconds to complete.</p>\n", (int) ESTIMATEDTIMETORUN);
	// Useful source http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#successful-controls

	if (numudpports > 0)
	{
		printf("<p>The list of UDP ports that will be tested are:</p>\n");

		// Start of table
		printf("<table border=\"1\">\n");
		for (portindex= 0; portindex < numudpports ; portindex++)
		{
			port = udpportlist[portindex].port_num;
			special = udpportlist[portindex].special;
			last = (portindex == (numudpports-1)) ? 1 : 0 ;

			if (position == 0) printf("<tr style=\"text-align:center\">\n");
			if (0 != special)
			{
				printf("<td width=\"%d%%\" title=\"%s\">Port %d[%d]</td>\n",COLUMNUDPPCT, udpportlist[portindex].port_desc, port, special);
			}
			else
			{
				printf("<td width=\"%d%%\" title=\"%s\">Port %d</td>\n",COLUMNUDPPCT, udpportlist[portindex].port_desc, port);
			}
			position++;
			if (position >= MAXUDPCOLS || last == 1) { printf("</tr>\n"); position=0; };
		}
		// end of table
		printf("</table>\n");
	}

	// Useful source http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#successful-controls
	printf("<p>The default list of TCP ports that will be tested are:</p>\n");

	// Start of table
	printf("<table border=\"1\">\n");
	position = 0;
	for (portindex= 0; portindex < numports ; portindex++)
	{
		port = portlist[portindex].port_num;
		special = portlist[portindex].special;
		last = (portindex == (numports-1)) ? 1 : 0 ;

		if (position == 0) printf("<tr style=\"text-align:center\">\n");
		if (0 != special)
		{
			printf("<td width=\"%d%%\" title=\"%s\">Port %d[%d]</td>\n",COLUMNPCT, portlist[portindex].port_desc, port, special);
		}
		else
		{
			printf("<td width=\"%d%%\" title=\"%s\">Port %d</td>\n",COLUMNPCT, portlist[portindex].port_desc, port);
		}

		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}
	// end of table
	printf("</table>\n");

	printf("<p style=\"font-weight:bold\">1. Select whether to include the default list of TCP ports, or not:</p>\n");

	printf("<form action=\""URIPATH"/"EXENAME"\" accept-charset=\"ISO-8859-1\" method=\"GET\">\n");
	printf("<input type=\"radio\" name=\"includeexisting\" value=\"1\" checked> Include default TCP ports listed above in the scan<br>\n");
	printf("<input type=\"radio\" name=\"includeexisting\" value=\"-1\"> Exclude default TCP ports, test only those specified below<br>\n");
	printf("<p style=\"font-weight:bold\">2. Enter any custom TCP ports you wish to scan (%d-%d inclusive). Duplicate or invalid ports will be discarded:</p>\n", MINVALIDPORT, MAXVALIDPORT);

	printf("<table>\n");
	position = 0;
	for (i = 0; i < NUMUSERDEFPORTS ; i++)
	{
		// Start of a new row, so insert the appropriate tag if required
		last = (i == (NUMUSERDEFPORTS-1)) ? 1 : 0;
		if (position == 0) printf("<tr style=\"text-align:center\">\n");

		printf("<td width=\"%d%%\"><input type=\"text\" value=\"\" size=\"5\" maxlength=\"5\" alt=\"Custom TCP port #%d\" name=\"customport%d\"></td>\n", COLUMNPCT, i, i);

		// Get ready for the next cell, add the end of row tag if required
		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}
	printf("</table>\n");
	#if (INCLUDETERMSOFUSE != 0)
	printf("<p style=\"font-weight:bold\">3. and finally, confirming that you accept the <a href=\"%s\" target=\"_blank\"> terms of usage</a>, please click on the Begin scan button:</p>\n", TERMSOFUSEURL);
	#else
	printf("<p style=\"font-weight:bold\">3. and finally, please click on the Begin scan button:</p>\n");
	#endif

	printf("<input type=\"submit\" value=\"Begin scan\">\n");
	printf("</form>\n");
}

#ifdef IPSCAN_HTML5_ENABLED
void create_html5_form(uint16_t numports, uint16_t numudpports, struct portlist_struc *portlist, struct portlist_struc *udpportlist)
{
	int i;
	uint16_t port,portindex;
	uint8_t special;
	int position = 0;
	int last = 0;

	printf("<title>IPv6 Port Scanner Version %s</title>\n", IPSCAN_VER);
	printf("</head>\n");
	printf("<body>\n");
	printf("<div>\n");

	printf("<h3 style=\"color:red\">IPv6 Port Scanner by Tim Chappell</h3>\n");

	printf("<p>Please note that this test may take up to %d seconds to complete.</p>\n", (int) ESTIMATEDTIMETORUN);
	// Useful source http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#successful-controls

	if (numudpports > 0)
	{
		printf("<p>The list of UDP ports that will be tested are:</p>\n");

		// Start of table
		printf("<table style=\"width:%dpx\">\n", IPSCAN_BODYDIV_WIDTH);
		for (portindex= 0; portindex < numudpports ; portindex++)
		{
			port = udpportlist[portindex].port_num;
			special = udpportlist[portindex].special;
			last = (portindex == (numudpports-1)) ? 1 : 0 ;

			if (position == 0) printf("<tr>\n");

			if (0 != special)
			{
				printf("<td title=\"%s\">Port %d[%d]</td>\n", udpportlist[portindex].port_desc, port, special);
			}
			else
			{
				printf("<td title=\"%s\">Port %d</td>\n", udpportlist[portindex].port_desc, port);
			}
			position++;
			if (position >= MAXUDPCOLS || last == 1) { printf("</tr>\n"); position=0; };
		}
		// end of table
		printf("</table>\n");
	}

	// Useful source http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#successful-controls
	printf("<p>The default list of TCP ports that will be tested are:</p>\n");

	// Start of table
	printf("<table style=\"width:%dpx\">\n", IPSCAN_BODYDIV_WIDTH);
	position = 0;
	for (portindex= 0; portindex < numports ; portindex++)
	{
		port = portlist[portindex].port_num;
		special = portlist[portindex].special;
		last = (portindex == (numports-1)) ? 1 : 0 ;

		if (position == 0) printf("<tr>\n");
		if (0 != special)
		{
			printf("<td title=\"%s\">Port %d[%d]</td>\n", portlist[portindex].port_desc, port, special);
		}
		else
		{
			printf("<td title=\"%s\">Port %d</td>\n", portlist[portindex].port_desc, port);
		}

		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}
	// end of table
	printf("</table>\n");

	printf("<p style=\"font-weight:bold\">1. Select whether to include the default list of TCP ports, or not:</p>\n");
	printf("<form onsubmit=\"return checkForm(this);\" action=\""URIPATH"/"EXENAME"\" accept-charset=\"ISO-8859-1\" method=\"GET\">\n");
	printf("<input type=\"radio\" name=\"includeexisting\" value=\"1\" checked> Include default TCP ports listed above in the scan<br>\n");
	printf("<input type=\"radio\" name=\"includeexisting\" value=\"-1\"> Exclude default TCP ports, test only those specified below<br>\n");
	printf("<p style=\"font-weight:bold\">2. Enter any custom TCP ports you wish to scan (%d-%d inclusive). Duplicate or invalid ports will be discarded:</p>\n", MINVALIDPORT, MAXVALIDPORT);

	printf("<table style=\"width:%dpx\">\n", IPSCAN_BODYDIV_WIDTH);
	position = 0;
	for (i = 0; i < NUMUSERDEFPORTS ; i++)
	{
		// Start of a new row, so insert the appropriate tag if required
		last = (i == (NUMUSERDEFPORTS-1)) ? 1 : 0;
		if (position == 0) printf("<tr style=\"text-align:center\">\n");

		printf("<td><input type=\"number\" value=\"\" min=\"%d\" max=\"%d\" alt=\"Custom TCP port #%d\" name=\"customport%d\" pattern=\"\\d+\"></td>\n", MINVALIDPORT, MAXVALIDPORT, i, i);

		// Get ready for the next cell, add the end of row tag if required
		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}
	printf("</table>\n");

	#if (INCLUDETERMSOFUSE != 0)
	printf("<p style=\"font-weight:bold\">3. Accept the <a href=\"%s\">Terms and Conditions</a> by ticking this box <input type=\"checkbox\" required name=\"termsaccepted\" value=\"1\">.</p>\n",TERMSOFUSEURL);
	#else
	printf("<p style=\"font-weight:bold\">3. and finally, please click on the Begin Scan button:</p>\n");
	#endif

	printf("<input style=\"color: white; font-size: 16px; text-align: center; border-radius: 1em; text-decoration: none; background-color: red; padding: 10px 15px; font-weight:bold\" type=\"submit\" value=\"Begin Scan\" >\n");
	printf("</form>\n");
	printf("</div>\n");
}
#endif
