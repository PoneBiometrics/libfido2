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
fido_str_array_append(fido_str_array_t *array, const char* object){
	if(array->ptr == NULL){
		array->ptr = malloc(sizeof(char*));
	}else{
		array->ptr = realloc(array->ptr, sizeof(char*) * (array->len+1));
	}
	array->ptr[array->len] = strdup(object);
	array->len += 1;
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


static int
fido_ble_dbus_get_fido_devices(sd_bus *bus, fido_str_array_t **result){
	_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
	_cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
	int r;
	fido_str_array_t *res = calloc(1, sizeof(fido_algo_array_t));
	*result = res;

	r = sd_bus_call_method(bus, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects", &error, &m, "");
	if (r < 0) {
		fido_log_debug("failed to get managed objects: %s\n", strerror(-r));
		return FIDO_ERR_INTERNAL;
	}

	sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}");
	while(sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}") >0){
		const char *object;
		sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &object);
		sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sa{sv}}");

		while(sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}") >0){
			const char *interface;
			sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &interface);

			if(strcmp(interface, "org.bluez.Device1")==0){
				sd_bus_message_enter_container(m,SD_BUS_TYPE_ARRAY, "{sv}");
				while (sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,"sv")>0){
					const char *property;
					sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &property);

					if(strcmp(property, "UUIDs")==0){
						_cleanup_(strv_freep) char **uuids;
						sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "as");
						sd_bus_message_read_strv(m, &uuids);
						for( size_t i = 0; uuids[i] !=NULL; i +=1){
							if(strcmp("0000fffd-0000-1000-8000-00805f9b34fb", uuids[i])==0){
								fido_str_array_append(res, object);
							}
						}
						sd_bus_message_exit_container(m);
					}else{
						sd_bus_message_skip(m,"v");
					}
					sd_bus_message_exit_container(m);
					sd_bus_message_exit_container(m);
				}
				
			}else{
				sd_bus_message_skip(m,"a{sv}");
			}
			sd_bus_message_exit_container(m);
		}
		sd_bus_message_exit_container(m);
		sd_bus_message_exit_container(m);
	}
	sd_bus_message_exit_container(m);
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


	_cleanup_(fido_str_array_freep) fido_str_array_t *fido_devices;
	fido_ble_dbus_get_fido_devices(bus, &fido_devices);
	for(size_t i = 0; i < fido_devices->len; i++){
		if (copy_info(&devlist[*olen], bus, fido_devices->ptr[i]) == 0) {
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
