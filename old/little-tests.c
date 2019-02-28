#include "contiki.h"
#include "sys/etimer.h"
#include "dev/leds.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#define SECONDS 40

char print_text[] = "We're counting up";
int i = 0;

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

PROCESS_THREAD(hidra_r, ev, data)
{ 
	PROCESS_BEGIN();
	static struct etimer et;

	SENSORS_ACTIVATE(button_sensor);
	
	PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));

	etimer_set(&et, CLOCK_SECOND*SECONDS); 
	while(1) {

		PROCESS_WAIT_EVENT();
		if(etimer_expired(&et)) {
		  leds_toggle(LEDS_RED);
		  etimer_reset(&et);
			i++;
			printf("%s: %d\n", print_text , i);
		}

		if((ev==sensors_event) && (data == &button_sensor)) {
			break;
		}
  }
  PROCESS_END();
}

