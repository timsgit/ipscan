//    ipscan - an http-initiated IPv6 port scanner.
//
//    Copyright (C) 2011 Tim Chappell.
//
//    This file is part of ipscan.
//
//    ipscan is free software: you can redistribute it and/or modify
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
//    along with ipscan.  If not, see <http://www.gnu.org/licenses/>.

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


// Include resultsstruct
extern struct rslt_struc resultsstruct[];

void create_html_common_header(void)
{
		printf("%s%c%c\n","Content-Type:text/html;charset=iso-8859-1",13,10);
		printf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
		printf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
		printf("<META NAME=\"AUTHOR\" CONTENT=\"Tim Chappell\">\n");
		printf("<META HTTP-EQUIV=\"CACHE-CONTROL\" CONTENT=\"NO-STORE, NO-CACHE, MUST-REVALIDATE, MAX-AGE=0\">\n");
		printf("<META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\">\n");
		printf("<META NAME=\"COPYRIGHT\" CONTENT=\"Copyright (C) 2011 Tim Chappell.\">\n");
		printf("<head>\n");
}

void create_json_header(void)
{
		printf("%s%c%c\n","Content-Type:text/html;charset=iso-8859-1",13,10);
}

void create_html_header(char * servername, uint64_t session, time_t timestamp, uint16_t numports, uint16_t *portlist, char * reconquery)
{
	uint16_t port,portindex,i;

	create_html_common_header();

	printf("<title>IPv6 Universal TCP Port Scanner Version %s</title>\n", VERSION);
	printf("<script type = \"text/javascript\" language=\"javascript\">\n");
	printf("<!--\n");
	printf("var myInterval = 0;\n");
	printf("var myBlink = 0;\n");
	printf("var fetches = 0;\n");
	printf("var request = \"\";\n");
	printf("var initreq = \"\";\n");
	// printf("var updateurl = \""DIRPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=\" + fetches;\n", session, (uint32_t)timestamp, reconquery);
	printf("var updateurl = \"\";\n");
	printf("var starturl = \""DIRPATH"/"EXENAME"?beginscan=%d&session=%"PRIu64"&starttime=%"PRIu32"&%s\";\n", MAGICBEGIN, session, (uint32_t)timestamp, reconquery);
	printf("var portlist = [");
	for (portindex=0; portindex<numports; portindex++)
	{
		port=portlist[portindex];
		if (portindex == 0) printf(" %d", port); else printf(" ,%d", port);
	}
	printf(" ];\n");
	printf("var state = [");
	for (portindex=0; portindex<numports; portindex++)
	{
		port=portlist[portindex];
		if (portindex == 0) printf(" %d", PORTUNKNOWN); else printf(" ,%d", PORTUNKNOWN);
	}
	printf(" ];\n");

	// additions
	printf("var retvals = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (i == 0) printf(" %d",resultsstruct[i].returnval); else printf(" ,%d",resultsstruct[i].returnval);
	}
	printf(" ];\n");

	printf("var labels = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (i == 0) printf(" \"%s\"",resultsstruct[i].label); else printf(" ,\"%s\"",resultsstruct[i].label);
	}
	printf(" ];\n");
	printf("var colours = [");
	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		if (i == 0) printf(" \"%s\"",resultsstruct[i].colour); else printf(" ,\"%s\"",resultsstruct[i].colour);
	}
	printf(" ];\n");
	// additions
	printf("function makeHttpObject()\n");
	printf("{\n");
	printf("	try {return new XMLHttpRequest();}\n");
	printf("	catch (error) {}\n");
	printf("	try {return new ActiveXObject(\"Msxml2.XMLHTTP\");}\n");
	printf("	catch (error) {}\n");
	printf("	try {return new ActiveXObject(\"Microsoft.XMLHTTP\");}\n");
	printf("	catch (error) {}\n");
	printf("	throw new Error(\"Could not create HTTP request object.\");\n");
	printf("}\n");

	printf("function blink()\n");
	printf("{\n");
	printf("	if (document.getElementById(\"scanstate\").style.color == \"red\")\n");
	printf("	{\n");
	printf("		document.getElementById(\"scanstate\").style.color = \"black\";\n");
	printf("	}\n");
	printf("	else\n");
	printf("	{\n");
	printf("		document.getElementById(\"scanstate\").style.color = \"red\";\n");
	printf("	}\n");
	printf("}\n");

	printf("function startTimer()\n");
	printf("{\n");
	printf("myInterval = window.setInterval( \"update()\", %d );\n", (JSONFETCHEVERY*1000) );
	printf("initreq = makeHttpObject();\n");
	printf("initreq.open( \"GET\", starturl, true);\n");
	printf("initreq.send(null);\n");
	printf("document.getElementById(\"scanstate\").innerHTML = \"RUNNING.\";\n");
	printf("document.getElementById(\"scanstate\").style.color=\"black\";\n");
	printf("myBlink = window.setInterval( \"blink()\", 1000 );\n");
	printf("} // end function startTimer\n");

	printf("function update()\n");
	printf("{\n");
	printf("var i = 0;\n");
	printf("++fetches;\n");
	printf("updateurl = \""DIRPATH"/"EXENAME"?session=%"PRIu64"&starttime=%"PRIu32"&%s&fetch=\" + fetches;\n", session, (uint32_t)timestamp,reconquery);
	printf("if (fetches >%d) {window.clearInterval(myInterval)};\n",(int)( (4 + (numports*TIMEOUTSECS) / JSONFETCHEVERY )) );
	printf("request = makeHttpObject();\n");
	// third param determines sync/async fetch true=async
	printf("request.open( \"GET\", updateurl, true);\n");
	// printf("request.setRequestHeader(\"Content-Type\", \"text/json;charset=UTF-8\");\n");
	printf("request.onreadystatechange = function()\n");
	printf("{\n");
	printf("	if (request.readyState == 4 && request.status == 200)\n");
	printf("	{\n");
	printf(" 		var lateststate = eval( '(' + request.responseText + ')' );\n");
	printf("		if (lateststate.length > 1);\n");
	printf("		{\n");
	printf("			if (lateststate.length > portlist.length)\n");
	printf("			{\n");
	printf("				window.clearInterval(myInterval);\n");
	printf("				window.clearInterval(myBlink);\n");
	printf("			}\n");
	printf("			for (i = 0 ; i < (lateststate.length -1); i++)\n");
	printf("			{\n");
	printf("				state[i] = lateststate[i];\n");
	printf("			}\n");
	printf("		}\n");
	printf("		var textupdate = \"UNKNOWN\";\n");
	printf("		var colourupdate = \"white\";\n");
	printf("		for (i = 0; i < %d ; i++)\n", numports);
	printf("		{\n");
	printf("			var result = state[i];\n");
	printf("			var elemid = \"port\" + portlist[i];\n");

	printf("			for (j = 0; j < retvals.length; j++)\n");
	printf("			{\n");
	printf("				if (retvals[j] == result)\n");
	printf("				{\n");
	printf("					textupdate = \"Port \" + portlist[i] + \" = \" + labels[j];\n");
	printf("					colourupdate = colours[j];\n");
	printf("				}\n");
	printf("			}\n");

	printf("			document.getElementById( elemid ).innerHTML = textupdate;\n");
	printf("			document.getElementById( elemid ).style.backgroundColor=colourupdate;\n");
	printf("		}\n");
	printf("		if (lateststate.length > portlist.length)\n");
	printf("		{\n");
	printf("			document.getElementById(\"scanstate\").innerHTML = \"COMPLETE.\";\n");
	printf("			document.getElementById(\"scanstate\").style.color=\"black\";\n");
	printf("		}\n");
	printf("	}\n");
	printf("}\n");
	printf("request.send(null);\n");
	printf("} // end function update\n");
	printf("// -->\n");
	printf("</script>\n");
	printf("<NOSCRIPT><HR>\n");
	printf("<P><H3><FONT COLOR=\"red\">Your browser does not support Javascript, or else it is disabled.</H3><FONT COLOR=\"black\"></P>\n");
	printf("<P>An alternative version of this IPv6 TCP port scanner which does not use Javascript is available from ");
	printf("the following <A href=\"%s/%s\">link.</A></P>\n", DIRPATH, EXETXTNAME);
	printf("<P>This alternative version does not support realtime in-browser updates and will take up to ");
	printf("%d seconds to return the results.</P>\n", (numports * TIMEOUTSECS) );
	printf("<HR>");
	printf("</NOSCRIPT>\n");
	printf("</HEAD>\n");

}


void create_results_key_table(char * hostname, time_t timestamp)
{
	int i;

	// Offer the opportunity for feedback
	printf("<P><B>If you have any queries related to the results of this scan, or suggestions for improvement/additions to its' functionality");
	printf(" then please <A href=\"mailto:%s?subject=Feedback on IPv6 scanner&body=host: %s, time: %s\">email me.</A></B></P>\n", EMAILADDRESS, hostname, asctime(localtime(&timestamp)) );

	printf("<P><TABLE border=\"1\" bordercolor=\"black\">\n");
	printf("<tr align=\"left\">\n");
	printf("<TD width=\"25%%\" bgcolor=\"white\">REPORTED STATE</TD><TD width=\"75%%\" bgcolor=\"white\">MEANING</TD>\n");
	printf("</tr>\n");

	for (i=0; PORTEOL != resultsstruct[i].returnval; i++)
	{
		printf("<TR align=\"left\">\n");
		printf("<TD width=\"25%%\" bgcolor=\"%s\">%s</TD><TD width=\"75%%\" bgcolor=\"white\"> %s</TD>\n",resultsstruct[i].colour,\
				resultsstruct[i].label, resultsstruct[i].description);
		printf("</TR>\n");
	}
	printf("</TABLE></P>\n");
}

void create_html_body(char * hostname, uint64_t session, time_t timestamp, uint16_t numports, uint16_t *portlist)
{
	time_t nowtime;
	uint16_t portindex;
	uint16_t port;
	int position = 0;
	int last = 0;

	printf("<body onload = \"startTimer()\">\n");
	printf("<H3>IPv6 TCP Port Scan Results</H3>\n");
	printf("<p>Results for host : %s</p>\n\n", hostname);

	nowtime = time(0);
	printf("<p>Scan beginning at: %s, expected to take up to %d seconds ...</p>\n", asctime(localtime(&timestamp)), numports);

	// Start of table
	printf("<p><table border=\"4\" bordercolor=\"black\">\n");

	for (portindex= 0; portindex < numports ; portindex++)
	{
		port = portlist[portindex];
		last = (portindex == (numports-1)) ? 1 : 0 ;

		if (position ==0) printf("<tr align=\"center\">\n");
		printf("<td width=\"%d%%\" bgcolor=\"%s\" id=\"port%d\">Port %d = %s</td>\n",COLUMNPCT,resultsstruct[PORTUNKNOWN].colour, port,port, resultsstruct[PORTUNKNOWN].label );
		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };

	}

	// end of table
	printf("</table></p>\n");

	printf("<br>\n");

	printf("<p><H3><table>\n");
	printf("<tr align=\"left\">\n");
	printf("<td>Scan is : </td><td id=\"scanstate\">IDLE.</td></H3>\n");
	printf("</tr>\n");
	printf("</table></H3></p>\n");

	// Create results key table
	create_results_key_table(hostname, timestamp);

}

void create_html_body_end(void)
{
	printf("</body>\n");
	printf("</html>\n");
}

void create_html_form(uint16_t numports, uint16_t *portlist)
{
	int i;
	uint16_t port,portindex;
	int position = 0;
	int last = 0;

	printf("<title>IPv6 Universal TCP Port Scanner Version %s</title>\n", VERSION);
	printf("</head>\n");
	printf("<body>\n");
	printf("<H3><font color=\"red\">IPv6 Universal TCP Port Scanner by Tim Chappell<font color=\"black\"></H3>\n");

	// Useful source http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#successful-controls
	printf("<P>The default list of TCP ports that will be tested are:");

	// Start of table
	printf("<table border=\"1\" bordercolor=\"black\">\n");
	for (portindex= 0; portindex < numports ; portindex++)
	{
		port = portlist[portindex];
		last = (portindex == (numports-1)) ? 1 : 0 ;

		if (position ==0) printf("<tr align=\"center\">\n");
		printf("<td width=\"%d%%\">Port %d</td>\n",COLUMNPCT,port);
		position++;
		if (position >= MAXCOLS || last == 1) { printf("</tr>\n"); position=0; };
	}
	// end of table
	printf("</table></p>\n");

	printf("<br>\n");
	printf("<P><B>1. Select whether to include the default list of ports, or not:</B></P>\n");

	printf("<FORM action=\""DIRPATH"/"EXENAME"\" accept-charset=\"ISO-8859-1\" method=\"GET\">\n");
	printf("<P>\n");
	printf("<INPUT type=\"radio\" name=\"includeexisting\" value=\"1\" checked> Include default ports listed above in the scan<BR>\n");
	printf("<INPUT type=\"radio\" name=\"includeexisting\" value=\"-1\"> Exclude default ports, test only those specified below<BR><BR>\n");
	printf("<P><B>2. Enter any custom TCP ports you wish to scan (%d-%d inclusive). Duplicate or invalid ports will be removed:</B></P>\n", MINVALIDPORT, MAXVALIDPORT);

	for (i = 0; i < NUMUSERDEFPORTS ; i++)
	{
		printf("<INPUT type=\"text\" value=\"\" size=\"5\" maxlength=\"5\" alt=\"Custom TCP port #%d\" name=\"customport%d\"><BR>\n", i, i);
	}
	printf("<P><B>3. and finally click on the Begin scan button:</B></P>\n");

	printf("<INPUT type=\"submit\" value=\"Begin scan\">\n");
	printf("</P>\n");
	printf("</FORM>\n");
}
