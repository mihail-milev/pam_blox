/* automatically generated by rust-bindgen 0.56.0 */

pub const __LINUX_PAM__: u32 = 1;
pub const __LINUX_PAM_MINOR__: u32 = 0;
pub const PAM_SUCCESS: u32 = 0;
pub const PAM_OPEN_ERR: u32 = 1;
pub const PAM_SYMBOL_ERR: u32 = 2;
pub const PAM_SERVICE_ERR: u32 = 3;
pub const PAM_SYSTEM_ERR: u32 = 4;
pub const PAM_BUF_ERR: u32 = 5;
pub const PAM_PERM_DENIED: u32 = 6;
pub const PAM_AUTH_ERR: u32 = 7;
pub const PAM_CRED_INSUFFICIENT: u32 = 8;
pub const PAM_AUTHINFO_UNAVAIL: u32 = 9;
pub const PAM_USER_UNKNOWN: u32 = 10;
pub const PAM_MAXTRIES: u32 = 11;
pub const PAM_NEW_AUTHTOK_REQD: u32 = 12;
pub const PAM_ACCT_EXPIRED: u32 = 13;
pub const PAM_SESSION_ERR: u32 = 14;
pub const PAM_CRED_UNAVAIL: u32 = 15;
pub const PAM_CRED_EXPIRED: u32 = 16;
pub const PAM_CRED_ERR: u32 = 17;
pub const PAM_NO_MODULE_DATA: u32 = 18;
pub const PAM_CONV_ERR: u32 = 19;
pub const PAM_AUTHTOK_ERR: u32 = 20;
pub const PAM_AUTHTOK_RECOVERY_ERR: u32 = 21;
pub const PAM_AUTHTOK_LOCK_BUSY: u32 = 22;
pub const PAM_AUTHTOK_DISABLE_AGING: u32 = 23;
pub const PAM_TRY_AGAIN: u32 = 24;
pub const PAM_IGNORE: u32 = 25;
pub const PAM_ABORT: u32 = 26;
pub const PAM_AUTHTOK_EXPIRED: u32 = 27;
pub const PAM_MODULE_UNKNOWN: u32 = 28;
pub const PAM_BAD_ITEM: u32 = 29;
pub const PAM_CONV_AGAIN: u32 = 30;
pub const PAM_INCOMPLETE: u32 = 31;
pub const _PAM_RETURN_VALUES: u32 = 32;
pub const PAM_SILENT: u32 = 32768;
pub const PAM_DISALLOW_NULL_AUTHTOK: u32 = 1;
pub const PAM_ESTABLISH_CRED: u32 = 2;
pub const PAM_DELETE_CRED: u32 = 4;
pub const PAM_REINITIALIZE_CRED: u32 = 8;
pub const PAM_REFRESH_CRED: u32 = 16;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: u32 = 32;
pub const PAM_SERVICE: u32 = 1;
pub const PAM_USER: u32 = 2;
pub const PAM_TTY: u32 = 3;
pub const PAM_RHOST: u32 = 4;
pub const PAM_CONV: u32 = 5;
pub const PAM_AUTHTOK: u32 = 6;
pub const PAM_OLDAUTHTOK: u32 = 7;
pub const PAM_RUSER: u32 = 8;
pub const PAM_USER_PROMPT: u32 = 9;
pub const PAM_FAIL_DELAY: u32 = 10;
pub const PAM_XDISPLAY: u32 = 11;
pub const PAM_XAUTHDATA: u32 = 12;
pub const PAM_AUTHTOK_TYPE: u32 = 13;
pub const PAM_DATA_SILENT: u32 = 1073741824;
pub const PAM_PROMPT_ECHO_OFF: u32 = 1;
pub const PAM_PROMPT_ECHO_ON: u32 = 2;
pub const PAM_ERROR_MSG: u32 = 3;
pub const PAM_TEXT_INFO: u32 = 4;
pub const PAM_RADIO_TYPE: u32 = 5;
pub const PAM_BINARY_PROMPT: u32 = 7;
pub const PAM_MAX_NUM_MSG: u32 = 32;
pub const PAM_MAX_MSG_SIZE: u32 = 512;
pub const PAM_MAX_RESP_SIZE: u32 = 512;
pub const PAM_AUTHTOK_RECOVER_ERR: u32 = 21;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_handle {
    _unused: [u8; 0],
}
pub type pam_handle_t = pam_handle;
extern "C" {
    pub fn pam_set_item(
        pamh: *mut pam_handle_t,
        item_type: ::std::os::raw::c_int,
        item: *const ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: ::std::os::raw::c_int,
        item: *mut *const ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const ::std::os::raw::c_char,
        prompt: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_strerror(
        pamh: *mut pam_handle_t,
        errnum: ::std::os::raw::c_int,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn pam_putenv(
        pamh: *mut pam_handle_t,
        name_value: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_getenv(
        pamh: *mut pam_handle_t,
        name: *const ::std::os::raw::c_char,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn pam_fail_delay(
        pamh: *mut pam_handle_t,
        musec_delay: ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_message {
    pub msg_style: ::std::os::raw::c_int,
    pub msg: *const ::std::os::raw::c_char,
}
#[test]
fn bindgen_test_layout_pam_message() {
    assert_eq!(
        ::std::mem::size_of::<pam_message>(),
        16usize,
        concat!("Size of: ", stringify!(pam_message))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_message>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_message))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_message>())).msg_style as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
            "::",
            stringify!(msg_style)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_message>())).msg as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
            "::",
            stringify!(msg)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_response {
    pub resp: *mut ::std::os::raw::c_char,
    pub resp_retcode: ::std::os::raw::c_int,
}
#[test]
fn bindgen_test_layout_pam_response() {
    assert_eq!(
        ::std::mem::size_of::<pam_response>(),
        16usize,
        concat!("Size of: ", stringify!(pam_response))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_response>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_response))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_response>())).resp as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_response>())).resp_retcode as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp_retcode)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_conv {
    pub conv: ::std::option::Option<
        unsafe extern "C" fn(
            num_msg: ::std::os::raw::c_int,
            msg: *mut *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub appdata_ptr: *mut ::std::os::raw::c_void,
}
#[test]
fn bindgen_test_layout_pam_conv() {
    assert_eq!(
        ::std::mem::size_of::<pam_conv>(),
        16usize,
        concat!("Size of: ", stringify!(pam_conv))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_conv>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_conv))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_conv>())).conv as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
            "::",
            stringify!(conv)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_conv>())).appdata_ptr as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
            "::",
            stringify!(appdata_ptr)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_xauth_data {
    pub namelen: ::std::os::raw::c_int,
    pub name: *mut ::std::os::raw::c_char,
    pub datalen: ::std::os::raw::c_int,
    pub data: *mut ::std::os::raw::c_char,
}
#[test]
fn bindgen_test_layout_pam_xauth_data() {
    assert_eq!(
        ::std::mem::size_of::<pam_xauth_data>(),
        32usize,
        concat!("Size of: ", stringify!(pam_xauth_data))
    );
    assert_eq!(
        ::std::mem::align_of::<pam_xauth_data>(),
        8usize,
        concat!("Alignment of ", stringify!(pam_xauth_data))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_xauth_data>())).namelen as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_xauth_data),
            "::",
            stringify!(namelen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_xauth_data>())).name as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_xauth_data),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_xauth_data>())).datalen as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_xauth_data),
            "::",
            stringify!(datalen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<pam_xauth_data>())).data as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(pam_xauth_data),
            "::",
            stringify!(data)
        )
    );
}
extern "C" {
    pub fn pam_start(
        service_name: *const ::std::os::raw::c_char,
        user: *const ::std::os::raw::c_char,
        pam_conversation: *const pam_conv,
        pamh: *mut *mut pam_handle_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_start_confdir(
        service_name: *const ::std::os::raw::c_char,
        user: *const ::std::os::raw::c_char,
        pam_conversation: *const pam_conv,
        confdir: *const ::std::os::raw::c_char,
        pamh: *mut *mut pam_handle_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_end(
        pamh: *mut pam_handle_t,
        pam_status: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_authenticate(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_setcred(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_acct_mgmt(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_open_session(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_close_session(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn pam_chauthtok(
        pamh: *mut pam_handle_t,
        flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}