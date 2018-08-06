//Simple web-server. Just for testing

#pragma once

char p_buffer[150];
#define P(str) (strcpy_P(p_buffer, PSTR(str)), p_buffer)

WiFiServer server(5111);

#define LENHEADER "Content-Length:"

// string buffers for receiving URL and arguments
char bufferUrl[256];
char bufferArgs[512];
char bufferHeader[512];
uint8_t raw[4096];
int urlChars = 0;
int argChars = 0;
int headerChars = 0;
int rawSize = 0;
uint8_t response[4096];
size_t responseLen = 0;

// number of characters read on the current line
int lineChars = 0;

// total # requests serviced
long requests = 0;

// connection state while receiving a request
int state = 0;

/*
  Typical request: GET /<request goes here>?firstArg=1&anotherArg=2 HTTP/1.1
  State 0 - connection opened
  State 1 - receiving URL
  State 2 - receiving Arguments
  State 3 - arguments and/or URL finished
  State 4 - client has ended request, waiting for server to respond
  State 5 - server has responded
  
  Example of what the server receives:
  
  GET /test.html HTTP/1.1
  Host: 192.168.1.23
  Connection: keep-alive
  Cache-Control: max-age=0
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
  Accept-Encoding: gzip, deflate, sdch
  Accept-Language: en-US,en;q=0.8
*/

WiFiClient client;

// 200 OK means the resource was located on the server and the browser (or service consumer) should expect a happy response
void sendHttpResponseOk(WiFiClient client)
{
  Serial.println(P("200 OK"));
  Serial.println();
  
  // send a standard http response header
  client.println(P("HTTP/1.1 200 OK"));
  client.println(P("Content-Type: text/html"));
  client.println(P("Connnection: keep-alive")); // keep connection open
  if (responseLen > 0) {
    client.print(P("Content-Length: "));
    client.println(responseLen);
  }
  client.println();
}

// 404 means it ain't here. quit asking.
void sendHttp404(WiFiClient client)
{
  Serial.println(P("404 Not Found"));
  Serial.println();
  
  client.println(P("HTTP/1.1 404 Not Found"));
  client.println(P("Content-Type: text/html"));
  client.println(P("Connnection: keep-alive")); // keep connection open
  client.println();
}

void respond(WiFiClient client)
{
  if (strcmp(bufferUrl, P("")) == 0)
  {
    // Requested: /  (DEFAULT PAGE)
    
    // send response header
    sendHttpResponseOk(client);

    // send html page
    // max length:    -----------------------------------------------------------------------------------------------------------------------------------------------------  (149 chars)
    client.println(P("<HTML><head><title>Welcome</title></head><body><h1>Welcome, visitor"));
    client.print(requests);
    client.println(P("!</h1>Click here to visit the <a href=/test.html>Test Page</a><p>"));
    client.println(P("String output is stored in progmem to conserve RAM. That's what all the P( ) stuff is about. Buffer is big enough for 149 chars at once. "));
    client.println(P("Be careful not to exceed!<p><font color=red>This web server is not secured for public access. Use at your own risk.</font> "));
    client.println(P("If you want to use this in an actual product, at least leave the gateway IP setting disabled. You should consider a design where the Arduino acts"));
    client.println(P("as the client, or maybe a design where the Arduino can only be contacted by a more fully-secured server.<p>Requests are echoed to the console"));
    client.println(P("with baud rate of 115200. Have fun!<p><img src='/54595677.jpg'/></body></html>"));
    client.println();
  }
  else if (strcmp(bufferUrl, P("pair-setup")) == 0)
  {
    pairing();
    if (responseLen > 0) {
      sendHttpResponseOk(client);
      client.write(response, responseLen);
    }
  }
  else if (strcmp(bufferUrl, P("test.html")) == 0)
  {
    // Requested: test.html
    
    // send response header
    sendHttpResponseOk(client);

    // send html page
    client.println(P("<HTML><head><title>Test Page</title></head><body><h1>Test Page</h1>"));
    client.println(P("<br><b>Resource:</b> "));
    client.println(bufferUrl);
    client.println(P("<br><b>Arguments:</b> "));
    client.println(bufferArgs);
    // max length:    -----------------------------------------------------------------------------------------------------------------------------------------------------  (149 chars)
    client.println(P("<br><br><form action='/test.html?' method='GET'>Test arguments: <input type=text name='arg1'/> <input type=submit value='GET'/></form>"));
    client.println(P("</body></html>"));
    client.println();
  }
  else
  {
    // All other requests - 404 not found
    
    // send 404 not found header (oops)
    sendHttp404(client);
    client.println(P("<HTML><head><title>Resource not found</title></head><body><h1>The requested resource was not found</h1>"));
    client.println(P("<br><b>Resource:</b> "));
    client.println(bufferUrl);
    client.println(P("<br><b>Arguments:</b> "));
    client.println(bufferArgs);
    client.println(P("</body></html>"));
    client.println();
  }
}

int8_t conn = -1;
uint32_t web() {
  WiFiClient newClient = server.available();
  if (newClient && newClient.connected() && (!client || newClient.remoteIP() != client.remoteIP() || newClient.remotePort() != client.remotePort())) {
    if (client) {
      Serial.print("Stop connection from ");
      Serial.print(client.remoteIP());
      Serial.print(":");
      Serial.println(client.remotePort());
      client.stop();
    }
    client = newClient;
    Serial.print("New incoming connection from ");
    Serial.print(client.remoteIP());
    Serial.print(":");
    Serial.println(client.remotePort());
  } else {
    if (client) Serial.print(".");
  }
  
  if (client) 
  {
    state = 0;
    urlChars = 0;
    argChars = 0;
    headerChars = 0;
    lineChars = 0;
    bufferUrl[0] = 0;
    bufferArgs[0] = 0;
    bufferHeader[0] = 0;
    rawSize = 0;
    responseLen = 0;

    //while (client.connected()) 
    if (client.connected()) 
    {
      //if (client.available()) 
      while (client.available()) 
      {
        // read and echo data received from the client
        char c = client.read();
        Serial.print(c);

        // ignore \r carriage returns, we only care about \n new lines
        if (c == '\r')
          continue;        
          
        // control what happens to the buffer:
        if (state == 0 && c == '/')
        {
          // Begin receiving URL
          state = 1; 
        }
        else if (state == 1 && c == '?')
        {
          // Begin receiving args
          state = 2;
        }
        else if ((state == 1 || state == 2) && c == ' ')
        {
          // Received full request URL and/or args
          state = 3;
        }
        else if (state == 1 && urlChars < 255)
        {
            // Receiving URL (allow up to 255 chars + null terminator)
            bufferUrl[urlChars++] = c;
            bufferUrl[urlChars] = 0;
        }
        else if (state == 2 && argChars < 511)
        {
            // Receiving Args (allow up to 511 chars + null terminator)
            bufferArgs[argChars++] = c;
            bufferArgs[argChars] = 0;
        }
        else if (state == 3 && c == '\n' && lineChars == 0)
        {
          // Received a line with no characters; this means the client has ended their request
          state = 4;
        }
        if (state == 3 && headerChars < 511) {
          if (c == '\n') {
            //Serial.println(bufferHeaer)
            if (strncmp(bufferHeader, P(LENHEADER), sizeof(LENHEADER) - 1) == 0) {
              rawSize  = atoi(bufferHeader + sizeof(LENHEADER));
              Serial.print("Data size: ");
              Serial.println(rawSize);
            }
            headerChars = 0;
            bufferHeader[0] = 0;
          } else {
            bufferHeader[headerChars++] = c;
            bufferHeader[headerChars] = 0;
          }
        }

        // record how many characters on the line so far:
        if (c == '\n')
          lineChars = 0;
        else
          lineChars++;

        // OK to respond
        if(state == 4)
        {
          // Response given
          state = 5; 
          if (client.readBytes(raw, rawSize) != rawSize) {
            Serial.println("Error getting raw data");
            rawSize = 0;
          } else {
            for (uint8_t i = 0; i < rawSize; i++) {
              Serial.print(raw[i], HEX);
              Serial.print(" ");
            }
            Serial.println();
          }
          // increment internally for fun purposes
          requests++;
          Serial.print(P("Request # "));
          Serial.print(requests);
          Serial.print(P(": "));
          Serial.println(bufferUrl);

          // handle the response
          respond(client);

          // exit the loop
          break;
        }
      }
    }
    
    // flush and close the connection:
    client.flush(); // Does flush is needed?
    //client.stop();
  }
  return 100;
}

uint32_t webInit() {
  taskAdd(web);
  server.begin();
  return RUN_DELETE;
}

