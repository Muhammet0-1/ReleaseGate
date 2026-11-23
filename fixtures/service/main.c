#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *edition = getenv("PARCEL_EDITION");
    const char *label = edition && strcmp(edition, "green") == 0 ? "green" : "blue";
    return printf("{\"service\":\"parcel-note\",\"edition\":\"%s\"}\n", label) < 0;
}
