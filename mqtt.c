#include "mqtt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/sha256.h"
#include "mqttconnectAzure.h"


#define MQTT_DUP_FLAG     1<<3
#define MQTT_QOS0_FLAG    0<<1
#define MQTT_QOS1_FLAG    1<<1
#define MQTT_QOS2_FLAG    2<<1

#define MQTT_RETAIN_FLAG  1

#define MQTT_CLEAN_SESSION  1<<1
#define MQTT_WILL_FLAG      1<<2
#define MQTT_WILL_RETAIN    1<<5
#define MQTT_USERNAME_FLAG  1<<7
#define MQTT_PASSWORD_FLAG  1<<6

static mqtt_broker_handle_t TRBroker;
extern mbedtls_ssl_context ssl;


uint8_t mqtt_num_rem_len_bytes(const uint8_t* buf) {
	uint8_t num_bytes = 1;
		
	if ((buf[1] & 0x80) == 0x80) {
		num_bytes++;
		if ((buf[2] & 0x80) == 0x80) {
			num_bytes ++;
			if ((buf[3] & 0x80) == 0x80) {
				num_bytes ++;
			}
		}
	}
	return num_bytes;
}

uint16_t mqtt_parse_rem_len(const uint8_t* buf) {
	uint16_t multiplier = 1;
	uint16_t value = 0;
	uint8_t digit;
	
	buf++;

	do {
		digit = *buf;
		value += (digit & 127) * multiplier;
		multiplier *= 128;
		buf++;
	} while ((digit & 128) != 0);

	return value;
}

uint16_t mqtt_parse_msg_id(const uint8_t* buf) {
	uint8_t type = MQTTParseMessageType(buf);
	uint8_t qos = MQTTParseMessageQos(buf);
	uint16_t id = 0;
		
	if(type >= MQTT_MSG_PUBLISH && type <= MQTT_MSG_UNSUBACK) {
		if(type == MQTT_MSG_PUBLISH) {
			if(qos != 0) {
				// fixed header length + Topic (UTF encoded)
				// = 1 for "flags" byte + rlb for length bytes + topic size
				uint8_t rlb = mqtt_num_rem_len_bytes(buf);
				uint8_t offset = *(buf+1+rlb)<<8;	// topic UTF MSB
				offset |= *(buf+1+rlb+1);			// topic UTF LSB
				offset += (1+rlb+2);					// fixed header + topic size
				id = *(buf+offset)<<8;				// id MSB
				id |= *(buf+offset+1);				// id LSB
			}
		} else {
			// fixed header length
			// 1 for "flags" byte + rlb for length bytes
			uint8_t rlb = mqtt_num_rem_len_bytes(buf);
			id = *(buf+1+rlb)<<8;	// id MSB
			id |= *(buf+1+rlb+1);	// id LSB
		}
	}
	return id;
}

uint16_t mqtt_parse_pub_topic(const uint8_t* buf, uint8_t* topic) {
	const uint8_t* ptr;
	uint16_t topic_len = mqtt_parse_pub_topic_ptr(buf, &ptr);
		
	if(topic_len != 0 && ptr != NULL) {
		memcpy(topic, ptr, topic_len);
	}
	
	return topic_len;
}

uint16_t mqtt_parse_pub_topic_ptr(const uint8_t* buf, const uint8_t **topic_ptr) {
	uint16_t len = 0;
	
	if(MQTTParseMessageType(buf) == MQTT_MSG_PUBLISH) {
		// fixed header length = 1 for "flags" byte + rlb for length bytes
		uint8_t rlb = mqtt_num_rem_len_bytes(buf);
		len = *(buf+1+rlb)<<8;	// MSB of topic UTF
		len |= *(buf+1+rlb+1);	// LSB of topic UTF
		// start of topic = add 1 for "flags", rlb for remaining length, 2 for UTF
		*topic_ptr = (buf + (1+rlb+2));
	} else {
		*topic_ptr = NULL;
	}
	return len;
}

uint16_t mqtt_parse_publish_msg(const uint8_t* buf, uint8_t* msg) {
	const uint8_t* ptr;
		
	uint16_t msg_len = mqtt_parse_pub_msg_ptr(buf, &ptr);
	
	if(msg_len != 0 && ptr != NULL) {
		memcpy(msg, ptr, msg_len);
	}
	
	return msg_len;
}

uint16_t mqtt_parse_pub_msg_ptr(const uint8_t* buf, const uint8_t **msg_ptr) {
	uint16_t len = 0;
	
	//printf("mqtt_parse_pub_msg_ptr\n");
	
	if(MQTTParseMessageType(buf) == MQTT_MSG_PUBLISH) {
		// message starts at
		// fixed header length + Topic (UTF encoded) + msg id (if QoS>0)
		uint8_t rlb = mqtt_num_rem_len_bytes(buf);
		uint8_t offset = (*(buf+1+rlb))<<8;	// topic UTF MSB
		offset |= *(buf+1+rlb+1);			// topic UTF LSB
		offset += (1+rlb+2);				// fixed header + topic size

		if(MQTTParseMessageQos(buf)) {
			offset += 2;					// add two bytes of msg id
		}

		*msg_ptr = (buf + offset);
				
		// offset is now pointing to start of message
		// length of the message is remaining length - variable header
		// variable header is offset - fixed header
		// fixed header is 1 + rlb
		// so, lom = remlen - (offset - (1+rlb))
      	len = mqtt_parse_rem_len(buf) - (offset-(rlb+1));
	} else {
		*msg_ptr = NULL;
	}
	return len;
}

void mqtt_init(mqtt_broker_handle_t* broker, const char* clientid) {
	// Connection options
	broker->alive = 300; // 300 seconds = 5 minutes
	broker->seq = 1; // Sequency for message indetifiers
	// Client options
	memset(broker->clientid, 0, sizeof(broker->clientid));
	memset(broker->username, 0, sizeof(broker->username));
	memset(broker->password, 0, sizeof(broker->password));
	if(clientid) {
		strncpy(broker->clientid, clientid, sizeof(broker->clientid));
	} else {
		strcpy(broker->clientid, MQTTCLIENTID);
	}
	//Will topic
	broker->clean_session = 1;
	//socsendcallback
	broker->send = mbedtls_ssl_write;
}

void mqtt_init_auth(mqtt_broker_handle_t* broker, const char* username, const char* password) {
	if(username && username[0] != '\0')
		strncpy(broker->username, username, sizeof(broker->username)-1);
	if(password && password[0] != '\0')
		strncpy(broker->password, password, sizeof(broker->password)-1);
}

void mqtt_set_alive(mqtt_broker_handle_t* broker, uint16_t alive) {
	broker->alive = alive;
}

int mqtt_connect(mqtt_broker_handle_t* broker)
{
	uint8_t flags = 0x00;
	uint8_t *packet = NULL;
	uint16_t packet_length = 0;	
	uint16_t clientidlen = strlen(broker->clientid);
	uint16_t usernamelen = strlen(broker->username);
	uint16_t passwordlen = strlen(broker->password);
	uint16_t payload_len = clientidlen + 2;
	// Variable header
	uint8_t var_header[10] = {
		//0x00,0x06,0x4d,0x51,0x49,0x73,0x64,0x70, // Protocol name: MQIsdp
		0x00,0x04,0x4d,0x51,0x54,0x54,
		//0x03, // Protocol version
		0x04,
	};
	uint8_t fixedHeaderSize = 2;    // Default size = one byte Message Type + one byte Remaining Length
	uint8_t remainLen = 0;
	uint8_t *fixed_header = NULL;
	uint16_t offset = 0;
#if 1
	// Preparing the flags
	if(usernamelen) {
		payload_len += usernamelen + 2;
		flags |= MQTT_USERNAME_FLAG;
	}
	if(passwordlen) {
		payload_len += passwordlen + 2;
		flags |= MQTT_PASSWORD_FLAG;
	}
#endif	
	if(broker->clean_session) {
		flags |= MQTT_CLEAN_SESSION;
	}

	var_header[7] = flags;
	var_header[8] = broker->alive>>8;
	var_header[9] = broker->alive&0xFF;

	remainLen = sizeof(var_header)+payload_len;



	if (remainLen > 127) {
	    fixedHeaderSize++;          // add an additional byte for Remaining Length
	}
	fixed_header = (uint8_t *)malloc(fixedHeaderSize);

	// Message Type
	*fixed_header = MQTT_MSG_CONNECT;

	// Remaining Length
	if (remainLen <= 127) {
	    *(fixed_header+1) = remainLen;
	} else {
	    // first byte is remainder (mod) of 128, then set the MSB to indicate more bytes
	    *(fixed_header+1) = remainLen % 128;
	    *(fixed_header+1) = *(fixed_header+1) | 0x80;
	    // second byte is number of 128s
	    *(fixed_header+2) = remainLen / 128;
	}

	packet_length = fixedHeaderSize+sizeof(var_header)+payload_len;
	packet = (uint8_t *)malloc(packet_length);
	memset(packet, 0, packet_length);
	memcpy(packet, fixed_header, fixedHeaderSize);
	free(fixed_header);	
	offset += fixedHeaderSize;
	memcpy(packet+offset, var_header, sizeof(var_header));
	offset += sizeof(var_header);
	// Client ID - UTF encoded
	packet[offset++] = clientidlen>>8;
	packet[offset++] = clientidlen&0xFF;
	memcpy(packet+offset, broker->clientid, clientidlen);
	offset += clientidlen;
#if 1
	if(usernamelen) {
		// Username - UTF encoded
		packet[offset++] = usernamelen>>8;
		packet[offset++] = usernamelen&0xFF;
		memcpy(packet+offset, broker->username, usernamelen);
		offset += usernamelen;
	}

	if(passwordlen) {
		// Password - UTF encoded
		packet[offset++] = passwordlen>>8;
		packet[offset++] = passwordlen&0xFF;
		memcpy(packet+offset, broker->password, passwordlen);
		offset += passwordlen;
	}
#endif
	// Send the packet
	if(broker->send(&ssl, packet, packet_length) < packet_length) {
		free(packet);
		return -1;
	}
	free(packet);
	return 1;
}

int mqtt_disconnect(mqtt_broker_handle_t* broker) {
	uint8_t packet[] = {
		MQTT_MSG_DISCONNECT, // Message Type, DUP flag, QoS level, Retain
		0x00 // Remaining length
	};

	// Send the packet
	if(broker->send(broker->socket_info, packet, sizeof(packet)) < sizeof(packet)) {
		return -1;
	}

	return 1;
}

int mqtt_ping(mqtt_broker_handle_t* broker) {
	uint8_t packet[] = {
		MQTT_MSG_PINGREQ, // Message Type, DUP flag, QoS level, Retain
		0x00 // Remaining length
	};

	// Send the packet
	if(broker->send(broker->socket_info, packet, sizeof(packet)) < sizeof(packet)) {
		return -1;
	}

	return 1;
}

int mqtt_publish(mqtt_broker_handle_t* broker, const char* topic, const char* msg, uint16_t msglen, uint8_t retain) {
	return mqtt_publish_with_qos(broker, topic, msg, msglen, retain, 0, NULL);
}

int mqtt_publish_with_qos(mqtt_broker_handle_t* broker, const char* topic, const char* msg, uint16_t msgl, uint8_t retain, uint8_t qos, uint16_t* message_id) {
	uint16_t topiclen = strlen(topic);
	//uint16_t msglen = strlen(msg);
	uint16_t msglen = msgl;
	uint8_t *var_header = NULL; // Topic size (2 bytes), utf-encoded topic
	uint8_t *fixed_header = NULL;
	uint8_t fixedHeaderSize = 0,var_headerSize = 0;    // Default size = one byte Message Type + one byte Remaining Length
	uint16_t remainLen = 0;
	uint8_t *packet = NULL;
	uint16_t packet_length = 0;

	uint8_t qos_flag = MQTT_QOS0_FLAG;
	uint8_t qos_size = 0; // No QoS included
	if(qos == 1) {
		qos_size = 2; // 2 bytes for QoS
		qos_flag = MQTT_QOS1_FLAG;
	}
	else if(qos == 2) {
		qos_size = 2; // 2 bytes for QoS
		qos_flag = MQTT_QOS2_FLAG;
	}

	// Variable header
	var_headerSize = topiclen+2+qos_size;
	var_header = (uint8_t *)malloc(var_headerSize);
	memset(var_header, 0, var_headerSize);
	*var_header = topiclen>>8;
	*(var_header+1) = topiclen&0xFF;
	memcpy(var_header+2, topic, topiclen);
	if(qos_size) {
		var_header[topiclen+2] = broker->seq>>8;
		var_header[topiclen+3] = broker->seq&0xFF;
		if(message_id) { // Returning message id
			*message_id = broker->seq;
		}
		broker->seq++;
	}

	// Fixed header
	// the remaining length is one byte for messages up to 127 bytes, then two bytes after that
	// actually, it can be up to 4 bytes but I'm making the assumption the embedded device will only
	// need up to two bytes of length (handles up to 16,383 (almost 16k) sized message)
	fixedHeaderSize = 2;    // Default size = one byte Message Type + one byte Remaining Length
	remainLen = var_headerSize+msglen;
	if (remainLen > 127) {
		fixedHeaderSize++;          // add an additional byte for Remaining Length
	}
	fixed_header = (uint8_t *)malloc(fixedHeaderSize);
    
	// Message Type, DUP flag, QoS level, Retain
	*fixed_header = MQTT_MSG_PUBLISH | qos_flag;
	if(retain) {
		*fixed_header  |= MQTT_RETAIN_FLAG;
	}
	// Remaining Length
	if (remainLen <= 127) {
	   *(fixed_header+1) = remainLen;
	} else {
	   // first byte is remainder (mod) of 128, then set the MSB to indicate more bytes
	   *(fixed_header+1) = remainLen % 128;
	   *(fixed_header+1) = *(fixed_header+1) | 0x80;
	   // second byte is number of 128s
	   *(fixed_header+2) = remainLen / 128;
	}

	packet_length = fixedHeaderSize+var_headerSize+msglen;
	//packet = (uint8_t *)malloc(packet_length);
	packet = (uint8_t *)malloc(packet_length);
	memset(packet, 0, packet_length);
	memcpy(packet, fixed_header, fixedHeaderSize);
	memcpy(packet+fixedHeaderSize, var_header, var_headerSize);
	memcpy(packet+fixedHeaderSize+var_headerSize, msg, msglen);
	free(var_header);
	free(fixed_header);
	// Send the packet
	if(broker->send(&ssl, packet, packet_length) < packet_length) {
		//free(packet);
		free(packet);
		return -1;
	}
	//free(packet);
	free(packet);
	return 1;
}

int mqtt_pubrel(mqtt_broker_handle_t* broker, uint16_t message_id) {
	uint8_t packet[4] = {
		MQTT_MSG_PUBREL | MQTT_QOS1_FLAG, // Message Type, DUP flag, QoS level, Retain
		0x02, // Remaining length
	};

	packet[2] = message_id>>8;
	packet[3] = message_id&0xFF;

	// Send the packet
	if(broker->send(broker->socket_info, packet, sizeof(packet)) < sizeof(packet)) {
		return -1;
	}

	return 1;
}

int mqtt_subscribe(mqtt_broker_handle_t* broker, const char* topic, uint16_t* message_id) {
	uint16_t topiclen = strlen(topic);
	uint8_t utftopicSize = 0;
	uint8_t *utf_topic = (uint8_t *)malloc(topiclen+3);// Topic size (2 bytes), utf-encoded topic, QoS byte
	// Variable header
	uint8_t *var_header = NULL; // Topic size (2 bytes), utf-encoded topic
	uint8_t *fixed_header = NULL;
	uint8_t fixedHeaderSize = 0,var_headerSize = 0;    // Default size = one byte Message Type + one byte Remaining Length
	uint8_t *packet = NULL;
	uint16_t packet_length = 0;

	var_headerSize =2;
	var_header = (uint8_t *)malloc(var_headerSize);
	memset(var_header, 0, var_headerSize);
	*var_header = broker->seq>>8;
	*(var_header+1) = broker->seq&0xFF;
	if(message_id) { // Returning message id
		*message_id = broker->seq;
	}
	broker->seq++;


	// utf topic
	memset(utf_topic, 0, topiclen+3);
	*utf_topic = topiclen>>8;
	*(utf_topic+1) = topiclen&0xFF;
	memcpy(utf_topic+2, topic, topiclen);
	
       fixedHeaderSize = 2; 
	fixed_header = (uint8_t *)malloc(fixedHeaderSize);
       *fixed_header = MQTT_MSG_SUBSCRIBE | MQTT_QOS1_FLAG; // Message Type, DUP flag, QoS level, Retai	
       *(fixed_header+1) = var_headerSize+topiclen+3;
	// Fixed header
	packet_length = fixedHeaderSize+var_headerSize+topiclen+3;
	packet = (uint8_t *)malloc(packet_length);
	memset(packet, 0, packet_length);
	memcpy(packet, fixed_header, fixedHeaderSize);
	memcpy(packet+fixedHeaderSize, var_header, var_headerSize);
	memcpy(packet+fixedHeaderSize+var_headerSize, utf_topic,topiclen+3);
	free(utf_topic);
	free(var_header);
	free(fixed_header);
	// Send the packet
	if(broker->send(&ssl, packet, packet_length) < packet_length) {
		free(packet);
		return -1;
	}
	free(packet);
	return 1;
}

int mqtt_unsubscribe(mqtt_broker_handle_t* broker, const char* topic, uint16_t* message_id) {
	uint16_t topiclen = strlen(topic);
	uint8_t *utf_topic = (uint8_t *)malloc(topiclen+2);// Topic size (2 bytes), utf-encoded topic	
	// Variable header
	uint8_t var_header[2]; // Message ID
	uint8_t fixedheadersize = 1+sizeof(var_header)+(topiclen+2);
	uint8_t *fixed_header = (uint8_t *)malloc(fixedheadersize);
	uint8_t packetsize = sizeof(var_header)+fixedheadersize+(topiclen+2);
	uint8_t *packet = (uint8_t *)malloc(packetsize);

	*fixed_header = MQTT_MSG_UNSUBSCRIBE | MQTT_QOS1_FLAG; // Message Type, DUP flag, QoS level, Retain
	var_header[0] = broker->seq>>8;
	var_header[1] = broker->seq&0xFF;
	if(message_id) { // Returning message id
		*message_id = broker->seq;
	}
	broker->seq++;

	// utf topic
	memset(utf_topic, 0, (topiclen+2));
	*utf_topic = topiclen>>8;
	*(utf_topic+1) = topiclen&0xFF;
	memcpy(utf_topic+2, topic, topiclen);

	// Fixed header	
	memset(packet, 0, packetsize);
	memcpy(packet, fixed_header, fixedheadersize);
	memcpy(packet+fixedheadersize, var_header, sizeof(var_header));
	memcpy(packet+fixedheadersize+sizeof(var_header), utf_topic, (topiclen+2));
	free(utf_topic);
	free(fixed_header);
	// Send the packet
	if(broker->send(broker->socket_info, packet, packetsize) < packetsize) {
		free(packet);
		return -1;
	}
	free(packet);
	return 1;
}

void PTMQTTInit(mqtt_broker_handle_t* broker, const char* clientid, const char* username, const char* password)
{
	mqtt_init(broker, clientid);
	mqtt_init_auth(broker, username, password);
}

void PTmqtttenter(void)
{
	PTMQTTInit(&TRBroker,"",MQTTUSERNAME,MQTTPASSWORD);
}

mqtt_broker_handle_t* PTMqttGetBroker(void)
{
	return &TRBroker;
}
