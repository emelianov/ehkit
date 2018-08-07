/*
 * HomeKit experiments scratch
 * 
 */
#define HOMEKIT_DEBUG

#include <Run.h>
#include <wolfssl.h>
#include "homekit.h"
#include "wifi.h"
#include "web.h"
#include "srpImpl.h"
#include "tools.h"

void setup()
{
  Serial.begin(74880);
  espWatchdogDisable();
  espOverclock();
  srpInit();
  espNormal();
  espWatchdogEnable();
  wifiInit();
  webInit();
}

void loop()
{
  taskExec();
  wdt_reset();
  yield();
}
