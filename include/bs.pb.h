// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: bs.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_bs_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_bs_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3011000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3011000 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/generated_enum_reflection.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_bs_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_bs_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxillaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[2]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_bs_2eproto;
namespace bs {
class BsRequest;
class BsRequestDefaultTypeInternal;
extern BsRequestDefaultTypeInternal _BsRequest_default_instance_;
class BsResponse;
class BsResponseDefaultTypeInternal;
extern BsResponseDefaultTypeInternal _BsResponse_default_instance_;
}  // namespace bs
PROTOBUF_NAMESPACE_OPEN
template<> ::bs::BsRequest* Arena::CreateMaybeMessage<::bs::BsRequest>(Arena*);
template<> ::bs::BsResponse* Arena::CreateMaybeMessage<::bs::BsResponse>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace bs {

enum BsResErr : int {
  NO_ERR = 0,
  AUTH_FAILED = 1,
  TARGET_CONNECT_ERR = 2,
  BsResErr_INT_MIN_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::PROTOBUF_NAMESPACE_ID::int32>::min(),
  BsResErr_INT_MAX_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::PROTOBUF_NAMESPACE_ID::int32>::max()
};
bool BsResErr_IsValid(int value);
constexpr BsResErr BsResErr_MIN = NO_ERR;
constexpr BsResErr BsResErr_MAX = TARGET_CONNECT_ERR;
constexpr int BsResErr_ARRAYSIZE = BsResErr_MAX + 1;

const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* BsResErr_descriptor();
template<typename T>
inline const std::string& BsResErr_Name(T enum_t_value) {
  static_assert(::std::is_same<T, BsResErr>::value ||
    ::std::is_integral<T>::value,
    "Incorrect type passed to function BsResErr_Name.");
  return ::PROTOBUF_NAMESPACE_ID::internal::NameOfEnum(
    BsResErr_descriptor(), enum_t_value);
}
inline bool BsResErr_Parse(
    const std::string& name, BsResErr* value) {
  return ::PROTOBUF_NAMESPACE_ID::internal::ParseNamedEnum<BsResErr>(
    BsResErr_descriptor(), name, value);
}
enum AType : int {
  ATYP_NONE = 0,
  IP_V4 = 1,
  DOMAINAME = 3,
  IP_V6 = 4,
  AType_INT_MIN_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::PROTOBUF_NAMESPACE_ID::int32>::min(),
  AType_INT_MAX_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::PROTOBUF_NAMESPACE_ID::int32>::max()
};
bool AType_IsValid(int value);
constexpr AType AType_MIN = ATYP_NONE;
constexpr AType AType_MAX = IP_V6;
constexpr int AType_ARRAYSIZE = AType_MAX + 1;

const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* AType_descriptor();
template<typename T>
inline const std::string& AType_Name(T enum_t_value) {
  static_assert(::std::is_same<T, AType>::value ||
    ::std::is_integral<T>::value,
    "Incorrect type passed to function AType_Name.");
  return ::PROTOBUF_NAMESPACE_ID::internal::NameOfEnum(
    AType_descriptor(), enum_t_value);
}
inline bool AType_Parse(
    const std::string& name, AType* value) {
  return ::PROTOBUF_NAMESPACE_ID::internal::ParseNamedEnum<AType>(
    AType_descriptor(), name, value);
}
// ===================================================================

class BsRequest :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:bs.BsRequest) */ {
 public:
  BsRequest();
  virtual ~BsRequest();

  BsRequest(const BsRequest& from);
  BsRequest(BsRequest&& from) noexcept
    : BsRequest() {
    *this = ::std::move(from);
  }

  inline BsRequest& operator=(const BsRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline BsRequest& operator=(BsRequest&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const BsRequest& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const BsRequest* internal_default_instance() {
    return reinterpret_cast<const BsRequest*>(
               &_BsRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(BsRequest& a, BsRequest& b) {
    a.Swap(&b);
  }
  inline void Swap(BsRequest* other) {
    if (other == this) return;
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline BsRequest* New() const final {
    return CreateMaybeMessage<BsRequest>(nullptr);
  }

  BsRequest* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<BsRequest>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const BsRequest& from);
  void MergeFrom(const BsRequest& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(BsRequest* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "bs.BsRequest";
  }
  private:
  inline ::PROTOBUF_NAMESPACE_ID::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_bs_2eproto);
    return ::descriptor_table_bs_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kPasswdFieldNumber = 1,
    kTargetAddrFieldNumber = 3,
    kUdpDataFieldNumber = 7,
    kAtypFieldNumber = 2,
    kTargetPortFieldNumber = 4,
    kLogidFieldNumber = 6,
  };
  // string passwd = 1;
  void clear_passwd();
  const std::string& passwd() const;
  void set_passwd(const std::string& value);
  void set_passwd(std::string&& value);
  void set_passwd(const char* value);
  void set_passwd(const char* value, size_t size);
  std::string* mutable_passwd();
  std::string* release_passwd();
  void set_allocated_passwd(std::string* passwd);
  private:
  const std::string& _internal_passwd() const;
  void _internal_set_passwd(const std::string& value);
  std::string* _internal_mutable_passwd();
  public:

  // bytes target_addr = 3;
  void clear_target_addr();
  const std::string& target_addr() const;
  void set_target_addr(const std::string& value);
  void set_target_addr(std::string&& value);
  void set_target_addr(const char* value);
  void set_target_addr(const void* value, size_t size);
  std::string* mutable_target_addr();
  std::string* release_target_addr();
  void set_allocated_target_addr(std::string* target_addr);
  private:
  const std::string& _internal_target_addr() const;
  void _internal_set_target_addr(const std::string& value);
  std::string* _internal_mutable_target_addr();
  public:

  // bytes udp_data = 7;
  void clear_udp_data();
  const std::string& udp_data() const;
  void set_udp_data(const std::string& value);
  void set_udp_data(std::string&& value);
  void set_udp_data(const char* value);
  void set_udp_data(const void* value, size_t size);
  std::string* mutable_udp_data();
  std::string* release_udp_data();
  void set_allocated_udp_data(std::string* udp_data);
  private:
  const std::string& _internal_udp_data() const;
  void _internal_set_udp_data(const std::string& value);
  std::string* _internal_mutable_udp_data();
  public:

  // .bs.AType atyp = 2;
  void clear_atyp();
  ::bs::AType atyp() const;
  void set_atyp(::bs::AType value);
  private:
  ::bs::AType _internal_atyp() const;
  void _internal_set_atyp(::bs::AType value);
  public:

  // int32 target_port = 4;
  void clear_target_port();
  ::PROTOBUF_NAMESPACE_ID::int32 target_port() const;
  void set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_target_port() const;
  void _internal_set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // uint64 logid = 6;
  void clear_logid();
  ::PROTOBUF_NAMESPACE_ID::uint64 logid() const;
  void set_logid(::PROTOBUF_NAMESPACE_ID::uint64 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::uint64 _internal_logid() const;
  void _internal_set_logid(::PROTOBUF_NAMESPACE_ID::uint64 value);
  public:

  // @@protoc_insertion_point(class_scope:bs.BsRequest)
 private:
  class _Internal;

  ::PROTOBUF_NAMESPACE_ID::internal::InternalMetadataWithArena _internal_metadata_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr passwd_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr target_addr_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr udp_data_;
  int atyp_;
  ::PROTOBUF_NAMESPACE_ID::int32 target_port_;
  ::PROTOBUF_NAMESPACE_ID::uint64 logid_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_bs_2eproto;
};
// -------------------------------------------------------------------

class BsResponse :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:bs.BsResponse) */ {
 public:
  BsResponse();
  virtual ~BsResponse();

  BsResponse(const BsResponse& from);
  BsResponse(BsResponse&& from) noexcept
    : BsResponse() {
    *this = ::std::move(from);
  }

  inline BsResponse& operator=(const BsResponse& from) {
    CopyFrom(from);
    return *this;
  }
  inline BsResponse& operator=(BsResponse&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const BsResponse& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const BsResponse* internal_default_instance() {
    return reinterpret_cast<const BsResponse*>(
               &_BsResponse_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(BsResponse& a, BsResponse& b) {
    a.Swap(&b);
  }
  inline void Swap(BsResponse* other) {
    if (other == this) return;
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline BsResponse* New() const final {
    return CreateMaybeMessage<BsResponse>(nullptr);
  }

  BsResponse* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<BsResponse>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const BsResponse& from);
  void MergeFrom(const BsResponse& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(BsResponse* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "bs.BsResponse";
  }
  private:
  inline ::PROTOBUF_NAMESPACE_ID::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_bs_2eproto);
    return ::descriptor_table_bs_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kErrMsgFieldNumber = 2,
    kTargetAddrFieldNumber = 4,
    kUdpDataFieldNumber = 6,
    kErrNoFieldNumber = 1,
    kAtypFieldNumber = 3,
    kTargetPortFieldNumber = 5,
  };
  // string err_msg = 2;
  void clear_err_msg();
  const std::string& err_msg() const;
  void set_err_msg(const std::string& value);
  void set_err_msg(std::string&& value);
  void set_err_msg(const char* value);
  void set_err_msg(const char* value, size_t size);
  std::string* mutable_err_msg();
  std::string* release_err_msg();
  void set_allocated_err_msg(std::string* err_msg);
  private:
  const std::string& _internal_err_msg() const;
  void _internal_set_err_msg(const std::string& value);
  std::string* _internal_mutable_err_msg();
  public:

  // bytes target_addr = 4;
  void clear_target_addr();
  const std::string& target_addr() const;
  void set_target_addr(const std::string& value);
  void set_target_addr(std::string&& value);
  void set_target_addr(const char* value);
  void set_target_addr(const void* value, size_t size);
  std::string* mutable_target_addr();
  std::string* release_target_addr();
  void set_allocated_target_addr(std::string* target_addr);
  private:
  const std::string& _internal_target_addr() const;
  void _internal_set_target_addr(const std::string& value);
  std::string* _internal_mutable_target_addr();
  public:

  // bytes udp_data = 6;
  void clear_udp_data();
  const std::string& udp_data() const;
  void set_udp_data(const std::string& value);
  void set_udp_data(std::string&& value);
  void set_udp_data(const char* value);
  void set_udp_data(const void* value, size_t size);
  std::string* mutable_udp_data();
  std::string* release_udp_data();
  void set_allocated_udp_data(std::string* udp_data);
  private:
  const std::string& _internal_udp_data() const;
  void _internal_set_udp_data(const std::string& value);
  std::string* _internal_mutable_udp_data();
  public:

  // .bs.BsResErr err_no = 1;
  void clear_err_no();
  ::bs::BsResErr err_no() const;
  void set_err_no(::bs::BsResErr value);
  private:
  ::bs::BsResErr _internal_err_no() const;
  void _internal_set_err_no(::bs::BsResErr value);
  public:

  // .bs.AType atyp = 3;
  void clear_atyp();
  ::bs::AType atyp() const;
  void set_atyp(::bs::AType value);
  private:
  ::bs::AType _internal_atyp() const;
  void _internal_set_atyp(::bs::AType value);
  public:

  // int32 target_port = 5;
  void clear_target_port();
  ::PROTOBUF_NAMESPACE_ID::int32 target_port() const;
  void set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_target_port() const;
  void _internal_set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // @@protoc_insertion_point(class_scope:bs.BsResponse)
 private:
  class _Internal;

  ::PROTOBUF_NAMESPACE_ID::internal::InternalMetadataWithArena _internal_metadata_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr err_msg_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr target_addr_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr udp_data_;
  int err_no_;
  int atyp_;
  ::PROTOBUF_NAMESPACE_ID::int32 target_port_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_bs_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// BsRequest

// string passwd = 1;
inline void BsRequest::clear_passwd() {
  passwd_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsRequest::passwd() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.passwd)
  return _internal_passwd();
}
inline void BsRequest::set_passwd(const std::string& value) {
  _internal_set_passwd(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.passwd)
}
inline std::string* BsRequest::mutable_passwd() {
  // @@protoc_insertion_point(field_mutable:bs.BsRequest.passwd)
  return _internal_mutable_passwd();
}
inline const std::string& BsRequest::_internal_passwd() const {
  return passwd_.GetNoArena();
}
inline void BsRequest::_internal_set_passwd(const std::string& value) {
  
  passwd_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsRequest::set_passwd(std::string&& value) {
  
  passwd_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsRequest.passwd)
}
inline void BsRequest::set_passwd(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  passwd_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsRequest.passwd)
}
inline void BsRequest::set_passwd(const char* value, size_t size) {
  
  passwd_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsRequest.passwd)
}
inline std::string* BsRequest::_internal_mutable_passwd() {
  
  return passwd_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsRequest::release_passwd() {
  // @@protoc_insertion_point(field_release:bs.BsRequest.passwd)
  
  return passwd_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsRequest::set_allocated_passwd(std::string* passwd) {
  if (passwd != nullptr) {
    
  } else {
    
  }
  passwd_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), passwd);
  // @@protoc_insertion_point(field_set_allocated:bs.BsRequest.passwd)
}

// .bs.AType atyp = 2;
inline void BsRequest::clear_atyp() {
  atyp_ = 0;
}
inline ::bs::AType BsRequest::_internal_atyp() const {
  return static_cast< ::bs::AType >(atyp_);
}
inline ::bs::AType BsRequest::atyp() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.atyp)
  return _internal_atyp();
}
inline void BsRequest::_internal_set_atyp(::bs::AType value) {
  
  atyp_ = value;
}
inline void BsRequest::set_atyp(::bs::AType value) {
  _internal_set_atyp(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.atyp)
}

// bytes target_addr = 3;
inline void BsRequest::clear_target_addr() {
  target_addr_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsRequest::target_addr() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.target_addr)
  return _internal_target_addr();
}
inline void BsRequest::set_target_addr(const std::string& value) {
  _internal_set_target_addr(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.target_addr)
}
inline std::string* BsRequest::mutable_target_addr() {
  // @@protoc_insertion_point(field_mutable:bs.BsRequest.target_addr)
  return _internal_mutable_target_addr();
}
inline const std::string& BsRequest::_internal_target_addr() const {
  return target_addr_.GetNoArena();
}
inline void BsRequest::_internal_set_target_addr(const std::string& value) {
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsRequest::set_target_addr(std::string&& value) {
  
  target_addr_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsRequest.target_addr)
}
inline void BsRequest::set_target_addr(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsRequest.target_addr)
}
inline void BsRequest::set_target_addr(const void* value, size_t size) {
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsRequest.target_addr)
}
inline std::string* BsRequest::_internal_mutable_target_addr() {
  
  return target_addr_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsRequest::release_target_addr() {
  // @@protoc_insertion_point(field_release:bs.BsRequest.target_addr)
  
  return target_addr_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsRequest::set_allocated_target_addr(std::string* target_addr) {
  if (target_addr != nullptr) {
    
  } else {
    
  }
  target_addr_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), target_addr);
  // @@protoc_insertion_point(field_set_allocated:bs.BsRequest.target_addr)
}

// int32 target_port = 4;
inline void BsRequest::clear_target_port() {
  target_port_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 BsRequest::_internal_target_port() const {
  return target_port_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 BsRequest::target_port() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.target_port)
  return _internal_target_port();
}
inline void BsRequest::_internal_set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  target_port_ = value;
}
inline void BsRequest::set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_target_port(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.target_port)
}

// uint64 logid = 6;
inline void BsRequest::clear_logid() {
  logid_ = PROTOBUF_ULONGLONG(0);
}
inline ::PROTOBUF_NAMESPACE_ID::uint64 BsRequest::_internal_logid() const {
  return logid_;
}
inline ::PROTOBUF_NAMESPACE_ID::uint64 BsRequest::logid() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.logid)
  return _internal_logid();
}
inline void BsRequest::_internal_set_logid(::PROTOBUF_NAMESPACE_ID::uint64 value) {
  
  logid_ = value;
}
inline void BsRequest::set_logid(::PROTOBUF_NAMESPACE_ID::uint64 value) {
  _internal_set_logid(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.logid)
}

// bytes udp_data = 7;
inline void BsRequest::clear_udp_data() {
  udp_data_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsRequest::udp_data() const {
  // @@protoc_insertion_point(field_get:bs.BsRequest.udp_data)
  return _internal_udp_data();
}
inline void BsRequest::set_udp_data(const std::string& value) {
  _internal_set_udp_data(value);
  // @@protoc_insertion_point(field_set:bs.BsRequest.udp_data)
}
inline std::string* BsRequest::mutable_udp_data() {
  // @@protoc_insertion_point(field_mutable:bs.BsRequest.udp_data)
  return _internal_mutable_udp_data();
}
inline const std::string& BsRequest::_internal_udp_data() const {
  return udp_data_.GetNoArena();
}
inline void BsRequest::_internal_set_udp_data(const std::string& value) {
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsRequest::set_udp_data(std::string&& value) {
  
  udp_data_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsRequest.udp_data)
}
inline void BsRequest::set_udp_data(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsRequest.udp_data)
}
inline void BsRequest::set_udp_data(const void* value, size_t size) {
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsRequest.udp_data)
}
inline std::string* BsRequest::_internal_mutable_udp_data() {
  
  return udp_data_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsRequest::release_udp_data() {
  // @@protoc_insertion_point(field_release:bs.BsRequest.udp_data)
  
  return udp_data_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsRequest::set_allocated_udp_data(std::string* udp_data) {
  if (udp_data != nullptr) {
    
  } else {
    
  }
  udp_data_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), udp_data);
  // @@protoc_insertion_point(field_set_allocated:bs.BsRequest.udp_data)
}

// -------------------------------------------------------------------

// BsResponse

// .bs.BsResErr err_no = 1;
inline void BsResponse::clear_err_no() {
  err_no_ = 0;
}
inline ::bs::BsResErr BsResponse::_internal_err_no() const {
  return static_cast< ::bs::BsResErr >(err_no_);
}
inline ::bs::BsResErr BsResponse::err_no() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.err_no)
  return _internal_err_no();
}
inline void BsResponse::_internal_set_err_no(::bs::BsResErr value) {
  
  err_no_ = value;
}
inline void BsResponse::set_err_no(::bs::BsResErr value) {
  _internal_set_err_no(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.err_no)
}

// string err_msg = 2;
inline void BsResponse::clear_err_msg() {
  err_msg_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsResponse::err_msg() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.err_msg)
  return _internal_err_msg();
}
inline void BsResponse::set_err_msg(const std::string& value) {
  _internal_set_err_msg(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.err_msg)
}
inline std::string* BsResponse::mutable_err_msg() {
  // @@protoc_insertion_point(field_mutable:bs.BsResponse.err_msg)
  return _internal_mutable_err_msg();
}
inline const std::string& BsResponse::_internal_err_msg() const {
  return err_msg_.GetNoArena();
}
inline void BsResponse::_internal_set_err_msg(const std::string& value) {
  
  err_msg_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsResponse::set_err_msg(std::string&& value) {
  
  err_msg_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsResponse.err_msg)
}
inline void BsResponse::set_err_msg(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  err_msg_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsResponse.err_msg)
}
inline void BsResponse::set_err_msg(const char* value, size_t size) {
  
  err_msg_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsResponse.err_msg)
}
inline std::string* BsResponse::_internal_mutable_err_msg() {
  
  return err_msg_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsResponse::release_err_msg() {
  // @@protoc_insertion_point(field_release:bs.BsResponse.err_msg)
  
  return err_msg_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsResponse::set_allocated_err_msg(std::string* err_msg) {
  if (err_msg != nullptr) {
    
  } else {
    
  }
  err_msg_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), err_msg);
  // @@protoc_insertion_point(field_set_allocated:bs.BsResponse.err_msg)
}

// .bs.AType atyp = 3;
inline void BsResponse::clear_atyp() {
  atyp_ = 0;
}
inline ::bs::AType BsResponse::_internal_atyp() const {
  return static_cast< ::bs::AType >(atyp_);
}
inline ::bs::AType BsResponse::atyp() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.atyp)
  return _internal_atyp();
}
inline void BsResponse::_internal_set_atyp(::bs::AType value) {
  
  atyp_ = value;
}
inline void BsResponse::set_atyp(::bs::AType value) {
  _internal_set_atyp(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.atyp)
}

// bytes target_addr = 4;
inline void BsResponse::clear_target_addr() {
  target_addr_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsResponse::target_addr() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.target_addr)
  return _internal_target_addr();
}
inline void BsResponse::set_target_addr(const std::string& value) {
  _internal_set_target_addr(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.target_addr)
}
inline std::string* BsResponse::mutable_target_addr() {
  // @@protoc_insertion_point(field_mutable:bs.BsResponse.target_addr)
  return _internal_mutable_target_addr();
}
inline const std::string& BsResponse::_internal_target_addr() const {
  return target_addr_.GetNoArena();
}
inline void BsResponse::_internal_set_target_addr(const std::string& value) {
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsResponse::set_target_addr(std::string&& value) {
  
  target_addr_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsResponse.target_addr)
}
inline void BsResponse::set_target_addr(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsResponse.target_addr)
}
inline void BsResponse::set_target_addr(const void* value, size_t size) {
  
  target_addr_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsResponse.target_addr)
}
inline std::string* BsResponse::_internal_mutable_target_addr() {
  
  return target_addr_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsResponse::release_target_addr() {
  // @@protoc_insertion_point(field_release:bs.BsResponse.target_addr)
  
  return target_addr_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsResponse::set_allocated_target_addr(std::string* target_addr) {
  if (target_addr != nullptr) {
    
  } else {
    
  }
  target_addr_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), target_addr);
  // @@protoc_insertion_point(field_set_allocated:bs.BsResponse.target_addr)
}

// int32 target_port = 5;
inline void BsResponse::clear_target_port() {
  target_port_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 BsResponse::_internal_target_port() const {
  return target_port_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 BsResponse::target_port() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.target_port)
  return _internal_target_port();
}
inline void BsResponse::_internal_set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  target_port_ = value;
}
inline void BsResponse::set_target_port(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_target_port(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.target_port)
}

// bytes udp_data = 6;
inline void BsResponse::clear_udp_data() {
  udp_data_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& BsResponse::udp_data() const {
  // @@protoc_insertion_point(field_get:bs.BsResponse.udp_data)
  return _internal_udp_data();
}
inline void BsResponse::set_udp_data(const std::string& value) {
  _internal_set_udp_data(value);
  // @@protoc_insertion_point(field_set:bs.BsResponse.udp_data)
}
inline std::string* BsResponse::mutable_udp_data() {
  // @@protoc_insertion_point(field_mutable:bs.BsResponse.udp_data)
  return _internal_mutable_udp_data();
}
inline const std::string& BsResponse::_internal_udp_data() const {
  return udp_data_.GetNoArena();
}
inline void BsResponse::_internal_set_udp_data(const std::string& value) {
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void BsResponse::set_udp_data(std::string&& value) {
  
  udp_data_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:bs.BsResponse.udp_data)
}
inline void BsResponse::set_udp_data(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:bs.BsResponse.udp_data)
}
inline void BsResponse::set_udp_data(const void* value, size_t size) {
  
  udp_data_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:bs.BsResponse.udp_data)
}
inline std::string* BsResponse::_internal_mutable_udp_data() {
  
  return udp_data_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* BsResponse::release_udp_data() {
  // @@protoc_insertion_point(field_release:bs.BsResponse.udp_data)
  
  return udp_data_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void BsResponse::set_allocated_udp_data(std::string* udp_data) {
  if (udp_data != nullptr) {
    
  } else {
    
  }
  udp_data_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), udp_data);
  // @@protoc_insertion_point(field_set_allocated:bs.BsResponse.udp_data)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace bs

PROTOBUF_NAMESPACE_OPEN

template <> struct is_proto_enum< ::bs::BsResErr> : ::std::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::bs::BsResErr>() {
  return ::bs::BsResErr_descriptor();
}
template <> struct is_proto_enum< ::bs::AType> : ::std::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::bs::AType>() {
  return ::bs::AType_descriptor();
}

PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_bs_2eproto
