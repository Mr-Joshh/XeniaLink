#pragma once
// XGI message payloads (the structs the XDK's XSession* wrappers pass to
// XMsgStartIORequestEx). Layouts from Xenia's xsession.h. XNADDR, XNKID,
// XSESSION_INFO and XSESSION_SEARCHRESULT come from the XDK headers.
#include <xtl.h>
#include <xonline.h>

#define XGI_APP_ID        0xFB
#define XLIVEBASE_APP_ID  0xFC

#define XGI_SESSION_CREATE_MSG     0x000B0010
#define XGI_SESSION_DELETE_MSG     0x000B0011
#define XGI_SESSION_JOIN_MSG       0x000B0012
#define XGI_SESSION_LEAVE_MSG      0x000B0013
#define XGI_SESSION_START_MSG      0x000B0014
#define XGI_SESSION_END_MSG        0x000B0015
#define XGI_SESSION_SEARCH_MSG     0x000B0016
#define XGI_SESSION_MODIFY_MSG     0x000B0018
#define XGI_SESSION_SEARCHBYID_MSG 0x000B001B
#define XGI_SESSION_SEARCHEX_MSG   0x000B001C
#define XGI_SESSION_DETAILS_MSG    0x000B001D
#define XGI_SESSION_MIGRATE_MSG    0x000B001E
#define XGI_USER_READ_STATS_MSG    0x000B0021
#define XGI_SESSION_WRITESTATS_MSG 0x000B0025

// XNKID high-byte type (Xenia xnet.h)
#define XNKID_ONLINE_PEER 0x80

// Session flags (XDK XSESSION_CREATE_*)
#define XSESSION_FLAG_HOST          0x00000001

struct XGI_SESSION_CREATE {
  DWORD obj_ptr;
  DWORD flags;
  DWORD num_slots_public;
  DWORD num_slots_private;
  DWORD user_index;
  DWORD session_info_ptr;   // XSESSION_INFO*
  DWORD nonce_ptr;          // ULONGLONG*
};

struct XGI_SESSION_STATE {  // Delete / Start / End
  DWORD obj_ptr;
  DWORD flags;
  ULONGLONG session_nonce;
};

struct XGI_SESSION_MANAGE {  // Join / Leave
  DWORD obj_ptr;
  DWORD array_count;
  DWORD xuid_array_ptr;      // ULONGLONG*  (remote join/leave)
  DWORD indices_array_ptr;   // DWORD*      (local join/leave)
  DWORD private_slots_array_ptr;  // BOOL*
};

struct XGI_SESSION_MODIFY {
  DWORD obj_ptr;
  DWORD flags;
  DWORD max_public_slots;
  DWORD max_private_slots;
};

struct XGI_SESSION_SEARCH {
  DWORD proc_index;
  DWORD user_index;
  DWORD num_results;
  WORD num_props;
  WORD num_ctx;
  DWORD props_ptr;
  DWORD ctx_ptr;
  DWORD results_buffer_size;
  DWORD search_results_ptr;  // XSESSION_SEARCHRESULT_HEADER*
};

struct XGI_SESSION_SEARCH_EX {
  XGI_SESSION_SEARCH session_search;
  DWORD num_users;
};

struct XGI_SESSION_SEARCH_BYID {
  DWORD user_index;
  XNKID session_id;
  DWORD results_buffer_size;
  DWORD search_results_ptr;
};
