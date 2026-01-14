#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

uint8_t *encode_message(const char *message) {
	uint16_t msg_len = strlen(message);
	
	uint8_t *buffer = (uint8_t *) malloc(sizeof(buffer) + msg_len);
	
	buffer[0] = (msg_len >> 8) & 0xFF;
	buffer[1] = msg_len & 0xFF;
	
	memcpy(buffer + 2, message, msg_len);
	
	return buffer;
}

int main() {
	const char *msg = "Hello, World!";
	uint8_t *encoded = encode_message(msg);
	
	printf("Encoded message length: %d bytes\n", encoded[0] << 8 | encoded[1]);
	
	free(encoded);
	return 0;
}

