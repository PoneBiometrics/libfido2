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


static int
fido_ble_dbus_get_children(sd_bus *bus, const char *path, fido_str_array_t **result){
	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
	int r;

	r = sd_bus_call_method(bus, "org.bluez", path, "org.freedesktop.DBus.Introspectable", "Introspect", &error, &m, "");
	if (r < 0) {
		fido_log_debug("failed to get children: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}


	const char *ans;
	r = sd_bus_message_read(m, "s", &ans);
	if (r < 0) {
		fido_log_debug("failed to get children reply: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}
	extract_nodes(ans,result);
	return FIDO_OK;
}

static void fido_str_array_freep(fido_str_array_t **x){
	//printf("cleaning up\n");
	fido_str_array_free(*x);
}

static void strv_freep(char *** strv){
	if (strv == NULL || *strv == NULL)
		return;
	for (size_t k = 0; (*strv)[k] !=  NULL; k++)
	{
		free((*strv)[k]);
	}
	free(*strv);
}

static int
ble_is_fido(sd_bus *bus, const char *ble_device) {
	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	_cleanup_(strv_freep) char **UUIDs;
	sd_bus_get_property_strv(bus, "org.bluez", ble_device, "org.bluez.Device1", "UUIDs", &error, &UUIDs);
	if (UUIDs == NULL)
		return 0;
	for (size_t k = 0; UUIDs[k] !=  NULL; k++)
	{
		if (strcmp("0000fffd-0000-1000-8000-00805f9b34fb", UUIDs[k])==0) {
			return 1;
		}
	}
	return 0;
}


static int
copy_info(fido_dev_info_t *di, sd_bus *bus,
    char *entry)
{
	int ok = -1;
	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	memset(di, 0, sizeof(*di));

	char *alias;
	sd_bus_get_property_string(bus, "org.bluez", entry, "org.bluez.Device1", "Alias", &error, &alias);


	// TODO: get name or fail
	if (asprintf(&di->path, "%s%s", FIDO_BLE_PREFIX, entry) == -1) {
		di->path = NULL;
		goto fail;
	}
	// TODO: extract Device Information Service(0x180A)/Manufacturer Name String (0x2A29)
	// "org.bluez" "/org/bluez/hci0/dev_CC_F9_57_89_8B_D8/service000b/char000c" "org.bluez.GattCharacteristic1", "ReadValue",
	di->manufacturer = strdup("BLE device:");

	// TODO: extract Device Information Service/Model Number String (0x2A24)
	di->product = strdup(alias);

	// TODO: extract vendor and product id from Device Information Service/PnP Id (0x2A50)
	//	di->vendor_id = (int16_t)id;
	//	di->product_id = (int16_t)id;

	ok = 0;
fail:
	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return ok;
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

	_cleanup_(fido_str_array_freep) fido_str_array_t *hcis;
	// inspect /org/bluez to get the bluetooth adaptor(s)
	fido_ble_dbus_get_children(bus, "/org/bluez", &hcis);
	// better approach instead: busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects a{oa{sa{sv}}}
	// { object => { interface => { property => variable value} } }
	// and scan for interface "org.bluez.Device1" property "UUIDs"
	for(size_t i = 0; i < hcis->len;i++){
		char hci_device[20];
		snprintf(hci_device, sizeof(hci_device),"/org/bluez/%s", hcis->ptr[i]);
		_cleanup_(fido_str_array_freep) fido_str_array_t *bt_devices;

		fido_ble_dbus_get_children(bus, hci_device, &bt_devices);
		for(size_t j=0; j < bt_devices->len; j++){
			char ble_device[40];
			snprintf(ble_device, sizeof(ble_device),"/org/bluez/%s/%s", hcis->ptr[i], bt_devices->ptr[j]);
			if(ble_is_fido(bus, ble_device)){
				if (copy_info(&devlist[*olen], bus, ble_device) == 0) {
					devlist[*olen].io = (fido_dev_io_t) {
						fido_ble_open,
						fido_ble_close,
						fido_ble_read,
						fido_ble_write,
					};
					devlist[*olen].transport = (fido_dev_transport_t) {
						fido_ble_rx,
						fido_ble_tx,
					};
					if (++(*olen) == ilen)
						break;
				}
			}				
		}
	}
	
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
