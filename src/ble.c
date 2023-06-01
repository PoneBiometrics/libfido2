/*
 * Copyright (c) 2023 Pone. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <systemd/sd-bus.h>
#include "fido.h"


#define _cleanup_(f) __attribute__((cleanup(f)))


bool
fido_is_ble(const char *path)
{
	return strncmp(path, FIDO_BLE_PREFIX, strlen(FIDO_BLE_PREFIX)) == 0;
}

int
fido_dev_set_ble(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}
	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_ble_open,
		fido_ble_close,
		fido_ble_read,
		fido_ble_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_ble_rx,
		fido_ble_tx,
	};

	return FIDO_OK;
}

static int
extract_nodes(const char* xml, fido_str_array_t ** nodes)
{
	fido_str_array_t *ret = (fido_str_array_t*) malloc(sizeof(fido_str_array_t));
	ret->len = 0;
	ret->ptr = NULL;
	*nodes = ret;
	for  (const char* a=xml;a!=NULL;)
	{
		const char* b=a;
		size_t len = 0;
		a = strstr(b,"<node name=\"");
		if(a==NULL){
			break;
		}
		b = strstr(a+12,"\"/>");
		if(b==NULL){
			break;
		}
		len = (size_t)(b - (a+12));
		ret->len += 1;
		if(ret->ptr == NULL){
			ret->ptr = malloc(sizeof(char*));
		}else{
			ret->ptr = realloc(ret->ptr, ret->len);
		}
		ret->ptr[ret->len-1] = malloc(len+1);
		memcpy(ret->ptr[ret->len-1],a+12,len);
		ret->ptr[ret->len-1][len] = 0;
		a = b;
	}
	return FIDO_OK;
}


int
fido_ble_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	*olen = 0;

	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;


	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
	_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
	int r;

	r = sd_bus_open_system(&bus);
	if (r  < 0) {
		fido_log_debug("failed to connect to system bus: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}


	// inspect /org/bluez to get the bluetooth adaptor(s)
	r = sd_bus_call_method(bus, "org.bluez", "/org/bluez", "org.freedesktop.DBus.Introspectable", "Introspect", &error, &m, "");
	if (r < 0) {
		fido_log_debug("failed to get hci devices: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}


	const char *ans;
	r = sd_bus_message_read(m, "s", &ans);
	if (r < 0) {
		fido_log_debug("failed to get hci devices reply: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}
	fido_str_array_t *hcis;
	extract_nodes(ans,&hcis);
	for(size_t i = 0; i < hcis->len;i++){
		char hci_device[20];
		snprintf(hci_device,sizeof(hci_device),"/org/bluez/%s", hcis->ptr[i]);
		r = sd_bus_call_method(bus, "org.bluez", hci_device, "org.freedesktop.DBus.Introspectable", "Introspect", &error, &m, "");
		if (r < 0) {
			fido_log_debug("failed to get bt devices: %s\n", strerror(-r));
			return FIDO_ERR_INTERNAL;
		}
		r = sd_bus_message_read(m, "s", &ans);
		if (r < 0) {
			fido_log_debug("failed to get bt devices reply: %s\n", strerror(-r));
			return FIDO_ERR_INTERNAL;
		}
		fido_str_array_t *bt_devices;
		extract_nodes(ans,&bt_devices);
		for(size_t j=0; j < bt_devices->len; j++){
			printf("ble:/org/bluez/%s/%s\n", hcis->ptr[i],bt_devices->ptr[j]);		
		}
		fido_str_array_free(bt_devices);
	}
	fido_str_array_free(hcis);
	

	// inspect /org/bluez/hci0 or similar to get all paired devices
	// get property


	return FIDO_OK;
}

void *
fido_ble_open(const char *path)
{
    if(path == NULL){
        return NULL;
    }
    return NULL;
}
void
fido_ble_close(void *handle)
{
    free(handle);
}

int
fido_ble_read(void *handle, unsigned char *buf, size_t len, int ms)
{
    (void)ms;
	if(handle ==NULL || buf == NULL || len==0 )
        return -1;
	// fido_log_debug("%s: rx_len", __func__);
	// fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: reading", __func__);
	return -1;
}

int
fido_ble_write(void *handle, const unsigned char *buf, size_t len)
{
    if (handle==NULL || buf==NULL) {
        return -1;
    }
	return (int)len;
}

int
fido_ble_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
    (void)d;
    (void)cmd;
    (void)buf;
    (void)count;
	return -1;
}

int
fido_ble_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
{
    (void)d;
    (void)cmd;
    (void)buf;
    (void)count;
    (void)ms;
	return -1;
}
