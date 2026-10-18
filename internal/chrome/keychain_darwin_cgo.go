//go:build darwin && cgo

package chrome

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// curd_safe_storage reads the generic password "Chrome Safe Storage" /
// "Chrome". On success it returns errSecSuccess and a malloc'ed buffer the
// caller must free.
static OSStatus curd_safe_storage(void **out, size_t *outLen) {
	CFStringRef service = CFStringCreateWithCString(NULL, "Chrome Safe Storage", kCFStringEncodingUTF8);
	CFStringRef account = CFStringCreateWithCString(NULL, "Chrome", kCFStringEncodingUTF8);
	const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
	const void *vals[] = {kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne};
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 5,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(query, &result);
	*out = NULL;
	*outLen = 0;
	if (st == errSecSuccess && result != NULL) {
		CFDataRef data = (CFDataRef)result;
		CFIndex n = CFDataGetLength(data);
		void *buf = malloc(n > 0 ? (size_t)n : 1);
		if (buf == NULL) {
			st = errSecAllocate;
		} else {
			CFDataGetBytes(data, CFRangeMake(0, n), (UInt8 *)buf);
			*out = buf;
			*outLen = (size_t)n;
		}
	}
	if (result != NULL) CFRelease(result);
	CFRelease(query);
	CFRelease(service);
	CFRelease(account);
	return st;
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

type keychainProvider struct{}

// KeychainProvider returns a provider that reads Chrome's "Chrome Safe
// Storage" item from the macOS keychain through the Security framework, so
// curd itself is the keychain client (and its code identity is what the ACL
// records).
func KeychainProvider() KeyProvider { return keychainProvider{} }

func (keychainProvider) Name() string { return "keychain" }

func (keychainProvider) Keys(context.Context) ([][]byte, error) {
	var buf unsafe.Pointer
	var n C.size_t
	if st := C.curd_safe_storage(&buf, &n); st != 0 { // errSecSuccess
		return nil, fmt.Errorf("%w (Security framework status %d)", errNoKeychain, int(st))
	}
	pw := C.GoBytes(buf, C.int(n))
	C.free(buf)
	key, err := deriveKey(string(pw), pbkdf2Iterations())
	for i := range pw {
		pw[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return [][]byte{key}, nil
}
