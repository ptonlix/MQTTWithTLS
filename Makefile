MQTTConnectwithTLS:
	gcc mbedtls-development/library/*.c *.c  -I mbedtls-development/include/ -o MQTTCNWithTLS
clean:
	rm ./MQTTCNWithTLS


