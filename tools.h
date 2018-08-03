#pragma once

void espOverclock() {
   REG_SET_BIT(0x3ff00014, BIT(0));
   //os_update_cpu_frequency(160);
}

void espNormal() {
    REG_CLR_BIT(0x3ff00014, BIT(0));
    //os_update_cpu_frequency(80);
}

void ICACHE_RAM_ATTR wdt_timer_isr(){
  wdt_reset();
}
void espWatchdogDisable() {
  timer1_disable();
  timer1_attachInterrupt(wdt_timer_isr);
  timer1_write(1200000);
  timer1_enable(TIM_DIV265, TIM_EDGE, TIM_LOOP);
  //wdt_disable();  
}
void espWatchdogEnable() {
  timer1_disable();
  timer1_detachInterrupt();
}
