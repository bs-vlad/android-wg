/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	// Add null checks for input parameters
	if (!ifname || !settings) {
		return -1; // Or another appropriate error code
	}

	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, NULL);
	if (!ifname_str) {
		return -1; // Out of memory
	}
	
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, NULL);
	if (!settings_str) {
		(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
		return -1; // Out of memory
	}

	jsize ifname_len = (*env)->GetStringUTFLength(env, ifname);
	jsize settings_len = (*env)->GetStringUTFLength(env, settings);

	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	});

	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	char *config = wgGetConfig(handle);
	if (!config) {
		return NULL;
	}
	
	jstring ret = (*env)->NewStringUTF(env, config);
	free(config);
	
	// Check if string creation was successful
	if ((*env)->ExceptionCheck(env)) {
		return NULL;
	}
	
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	char *version = wgVersion();
	if (!version) {
		return NULL;
	}
	
	jstring ret = (*env)->NewStringUTF(env, version);
	free(version);
	
	// Check if string creation was successful
	if ((*env)->ExceptionCheck(env)) {
		return NULL;
	}
	
	return ret;
}
