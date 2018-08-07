#pragma once

void homekit_random_fill(uint8_t *data, size_t size) {
    uint32_t x;
    for (int i=0; i<size; i+=sizeof(x)) {
        x = secureRandom(255);
        memcpy(data+i, &x, (size-i >= sizeof(x)) ? sizeof(x) : size-i);
    }
}

char *homekit_accessory_id_generate() {
    char* accessory_id = (char*)malloc(18);

    byte buf[6];
    homekit_random_fill(buf, sizeof(buf));

    snprintf(accessory_id, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    Serial.printf("Generated new accessory ID: %s", accessory_id);
    return accessory_id;
}

