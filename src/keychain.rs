use std::ffi::{CString, c_void};
use failure::Error;
use std::ptr;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemDelete(query: *const c_void) -> i32;

    static kSecClass: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecValueData: *const c_void;
    static kSecReturnData: *const c_void;
    static kCFBooleanTrue: *const c_void;
    static kSecAttrAccessGroup: *const c_void;
}

const ERR_SUCCESS: i32 = 0;

pub fn add_keychain_item(service: &str, account: &str, secret: &str) -> Result<(), Error> {
  let service = CString::new(service).unwrap();
  let account = CString::new(account).unwrap();
  let secret_bytes = secret.as_bytes();

  let cf_service = unsafe {
      CFStringCreateWithCString(ptr::null(), service.as_ptr(), 0x08000100) // UTF-8 encoding
  };
  let cf_account = unsafe {
      CFStringCreateWithCString(ptr::null(), account.as_ptr(), 0x08000100) // UTF-8 encoding
  };
  let cf_data = unsafe { CFDataCreate(ptr::null(), secret_bytes.as_ptr(), secret_bytes.len()) };
  let cf_access_group = unsafe {
      CFStringCreateWithCString(
          ptr::null(),
          "7WV56FL599.keychain_tool".as_ptr() as *const i8, // Fixed pointer type
          0x08000100,
      )
  };

  assert!(!cf_service.is_null(), "Failed to create CFString for service");
  assert!(!cf_account.is_null(), "Failed to create CFString for account");
  assert!(!cf_data.is_null(), "Failed to create CFData for secret");
  assert!(!cf_access_group.is_null(), "Failed to create CFString for access group");

  let attributes = vec![
      (unsafe { kSecClass }, unsafe { kSecClassGenericPassword }),
      (unsafe { kSecAttrService }, cf_service),
      (unsafe { kSecAttrAccount }, cf_account),
      (unsafe { kSecValueData }, cf_data),
      (unsafe { kSecAttrAccessGroup }, cf_access_group), // Added access group
  ];

  let attributes_ptr = attributes_to_dict(&attributes);
  assert!(!attributes_ptr.is_null(), "CFDictionary creation failed!");

  unsafe {
      let mut result: *mut c_void = ptr::null_mut();
      let status = SecItemAdd(attributes_ptr, &mut result as *mut *mut c_void as *mut *const c_void);

      CFRelease(attributes_ptr);  // Release dictionary
      CFRelease(cf_service);      // Release service string
      CFRelease(cf_account);      // Release account string
      CFRelease(cf_data);         // Release data
      CFRelease(cf_access_group); // Release access group string

      if status == ERR_SUCCESS {
          Ok(())
      } else {
          Err(failure::err_msg(format!("SecItemAdd failed with status: {}", status)))
      }
  }
}

pub fn get_keychain_item(service: &str, account: &str) -> Result<String, Error> {
  let service = CString::new(service).unwrap();
  let account = CString::new(account).unwrap();

  let cf_service = unsafe {
      CFStringCreateWithCString(ptr::null(), service.as_ptr() as *const i8, 0x08000100) // UTF-8 encoding
  };
  let cf_account = unsafe {
      CFStringCreateWithCString(ptr::null(), account.as_ptr() as *const i8, 0x08000100) // UTF-8 encoding
  };

  assert!(!cf_service.is_null(), "Failed to create CFString for service");
  assert!(!cf_account.is_null(), "Failed to create CFString for account");

  let query = vec![
      (unsafe { kSecClass }, unsafe { kSecClassGenericPassword }),
      (unsafe { kSecAttrService }, cf_service),
      (unsafe { kSecAttrAccount }, cf_account),
      (unsafe { kSecReturnData }, unsafe { kCFBooleanTrue }),
  ];

  let query_ptr = attributes_to_dict(&query);
  assert!(!query_ptr.is_null(), "CFDictionary creation failed for query!");

  unsafe {
      let mut result: *mut c_void = ptr::null_mut();
      let status = SecItemCopyMatching(query_ptr, &mut result as *mut *mut c_void as *mut *const c_void);

      CFRelease(query_ptr);   // Release query dictionary
      CFRelease(cf_service); // Release service string
      CFRelease(cf_account); // Release account string

      if status == ERR_SUCCESS {
          assert!(!result.is_null(), "SecItemCopyMatching returned a null result");

          // Convert the result to a Rust String
          let data_ptr = CFDataGetBytePtr(result);
          let data_len = CFDataGetLength(result);
          let bytes = std::slice::from_raw_parts(data_ptr, data_len);
          let secret = String::from_utf8_lossy(bytes).to_string();

          CFRelease(result); // Release result data

          Ok(secret)
      } else {
          Err(failure::err_msg(format!("SecItemCopyMatching failed with status: {}", status)))
      }
  }
}

// Helpers for Keychain Constants and Conversions

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *const c_void);
    fn CFDataGetLength(data: *const c_void) -> usize;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
}

extern "C" {
  fn CFDictionaryCreate(
      allocator: *const c_void,
      keys: *const *const c_void,
      values: *const *const c_void,
      count: usize,
      key_callbacks: *const c_void,
      value_callbacks: *const c_void,
  ) -> *const c_void;

  fn CFStringCreateWithCString(
      allocator: *const c_void,
      cstr: *const i8,
      encoding: u32,
  ) -> *const c_void;

  fn CFDataCreate(
      allocator: *const c_void,
      bytes: *const u8,
      length: usize,
  ) -> *const c_void;
}

fn attributes_to_dict(attrs: &[(/* key: */ *const c_void, /* value: */ *const c_void)]) -> *const c_void {
  let keys: Vec<*const c_void> = attrs.iter().map(|(key, _)| *key).collect();
  let values: Vec<*const c_void> = attrs.iter().map(|(_, value)| *value).collect();

  unsafe {
      CFDictionaryCreate(
          ptr::null(),
          keys.as_ptr(),
          values.as_ptr(),
          attrs.len(),
          ptr::null(),
          ptr::null(),
      )
  }
}

fn CFDataToString(data: *const c_void) -> String {
    unsafe {
        let length = CFDataGetLength(data);
        let bytes = CFDataGetBytePtr(data);
        String::from_utf8(Vec::from_raw_parts(bytes as *mut u8, length, length)).unwrap()
    }
}
