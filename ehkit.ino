/*
 * HomeKit experiments scratch
 * 
 */

#include <Run.h>
#include "srp.h"
#include "homekit.h"
#include "wifi.h"
#include "web.h"

void setup()
{
  Serial.begin(74880);
  wifiInit();
  webInit();
}

void loop()
{
  taskExec();
}
