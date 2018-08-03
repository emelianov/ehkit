// Wi-Fi setup
// mDNS (static values for testing) setup

#pragma once

#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <time.h>

String sysName = "ehweb";

uint32_t wifiWait() {
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
   
    if (!MDNS.begin(sysName.c_str())) {
      Serial.print("[mDNS: failed]");
    } else {
      //MDNS.addService("http", "tcp", 80);  // Add service to MDNS-SD
      Serial.print("[mDNS: started]");
    }
        #ifdef ESP8266
    //MDNS.addService("http", "tcp", 80);
    MDNS.addService("hap", "tcp", 5111); //5111
    //c#=1s#=1ff=0sf=0ci=1
    // Add service to MDNS-SD
    MDNS.addServiceTxt("hap", "tcp", "c#", "1");
    MDNS.addServiceTxt("hap", "tcp", "s#", "1");
    MDNS.addServiceTxt("hap", "tcp", "ff", "0");
    MDNS.addServiceTxt("hap", "tcp", "sf", "1");
    MDNS.addServiceTxt("hap", "tcp", "ci", "1");
    MDNS.addServiceTxt("hap", "tcp", "md", "esp");
    MDNS.addServiceTxt("hap", "tcp", "id", "30:ae:a4:3:2b:9c");
    #else
    MDNS.addService("_http", "_tcp", 80);
    MDNS.addService("_hap", "_tcp", 5111);
    //c#=1s#=1ff=0sf=0ci=1
    const char * arduTxtData[7] = {
            "c#=1",
            "s#=1",
            "ff=0",
            "sf=1",
            "ci=1",
            "md=esp32",
            "id=30:ae:a4:3:2b:9c"
      };
      mdns_service_txt_set(MDNS.mdns, "_hap", "_tcp", 7, arduTxtData);
    #endif
    return RUN_DELETE;
  }
  Serial.print(".");
  return 500;
}

uint32_t wifiInit() {
    WiFi.begin();
    taskAdd(wifiWait);
    return RUN_DELETE;
}

