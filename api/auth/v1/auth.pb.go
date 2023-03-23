// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.0
// 	protoc        v3.21.9
// source: auth/v1/auth.proto

package v1

import (
	_ "github.com/go-kratos/kratos/v2/errors"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type VerifyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VerifyBody *VerifyRequest_VerifyBody `protobuf:"bytes,1,opt,name=verify_body,json=verifyBody,proto3" json:"verify_body,omitempty"`
}

func (x *VerifyRequest) Reset() {
	*x = VerifyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_v1_auth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyRequest) ProtoMessage() {}

func (x *VerifyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_v1_auth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyRequest.ProtoReflect.Descriptor instead.
func (*VerifyRequest) Descriptor() ([]byte, []int) {
	return file_auth_v1_auth_proto_rawDescGZIP(), []int{0}
}

func (x *VerifyRequest) GetVerifyBody() *VerifyRequest_VerifyBody {
	if x != nil {
		return x.VerifyBody
	}
	return nil
}

type VerifyReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Access bool              `protobuf:"varint,1,opt,name=Access,proto3" json:"Access,omitempty"`
	User   *VerifyReply_User `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
}

func (x *VerifyReply) Reset() {
	*x = VerifyReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_v1_auth_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyReply) ProtoMessage() {}

func (x *VerifyReply) ProtoReflect() protoreflect.Message {
	mi := &file_auth_v1_auth_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyReply.ProtoReflect.Descriptor instead.
func (*VerifyReply) Descriptor() ([]byte, []int) {
	return file_auth_v1_auth_proto_rawDescGZIP(), []int{1}
}

func (x *VerifyReply) GetAccess() bool {
	if x != nil {
		return x.Access
	}
	return false
}

func (x *VerifyReply) GetUser() *VerifyReply_User {
	if x != nil {
		return x.User
	}
	return nil
}

type VerifyRequest_VerifyBody struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessToken string `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	ApiUrl      string `protobuf:"bytes,2,opt,name=api_url,json=apiUrl,proto3" json:"api_url,omitempty"`
	Tenant      string `protobuf:"bytes,3,opt,name=tenant,proto3" json:"tenant,omitempty"`
	ClientIp    string `protobuf:"bytes,4,opt,name=client_ip,json=clientIp,proto3" json:"client_ip,omitempty"`
}

func (x *VerifyRequest_VerifyBody) Reset() {
	*x = VerifyRequest_VerifyBody{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_v1_auth_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyRequest_VerifyBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyRequest_VerifyBody) ProtoMessage() {}

func (x *VerifyRequest_VerifyBody) ProtoReflect() protoreflect.Message {
	mi := &file_auth_v1_auth_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyRequest_VerifyBody.ProtoReflect.Descriptor instead.
func (*VerifyRequest_VerifyBody) Descriptor() ([]byte, []int) {
	return file_auth_v1_auth_proto_rawDescGZIP(), []int{0, 0}
}

func (x *VerifyRequest_VerifyBody) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *VerifyRequest_VerifyBody) GetApiUrl() string {
	if x != nil {
		return x.ApiUrl
	}
	return ""
}

func (x *VerifyRequest_VerifyBody) GetTenant() string {
	if x != nil {
		return x.Tenant
	}
	return ""
}

func (x *VerifyRequest_VerifyBody) GetClientIp() string {
	if x != nil {
		return x.ClientIp
	}
	return ""
}

type VerifyReply_User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ID      string `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Subject string `protobuf:"bytes,2,opt,name=Subject,proto3" json:"Subject,omitempty"`
}

func (x *VerifyReply_User) Reset() {
	*x = VerifyReply_User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_v1_auth_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VerifyReply_User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyReply_User) ProtoMessage() {}

func (x *VerifyReply_User) ProtoReflect() protoreflect.Message {
	mi := &file_auth_v1_auth_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyReply_User.ProtoReflect.Descriptor instead.
func (*VerifyReply_User) Descriptor() ([]byte, []int) {
	return file_auth_v1_auth_proto_rawDescGZIP(), []int{1, 0}
}

func (x *VerifyReply_User) GetID() string {
	if x != nil {
		return x.ID
	}
	return ""
}

func (x *VerifyReply_User) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

var File_auth_v1_auth_proto protoreflect.FileDescriptor

var file_auth_v1_auth_proto_rawDesc = []byte{
	0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x61, 0x70, 0x69, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76,
	0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x13, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd6, 0x01, 0x0a, 0x0d, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x46, 0x0a, 0x0b, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79,
	0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x42, 0x6f,
	0x64, 0x79, 0x52, 0x0a, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x42, 0x6f, 0x64, 0x79, 0x1a, 0x7d,
	0x0a, 0x0a, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x21, 0x0a, 0x0c,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12,
	0x17, 0x0a, 0x07, 0x61, 0x70, 0x69, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x61, 0x70, 0x69, 0x55, 0x72, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x65, 0x6e, 0x61,
	0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74,
	0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x70, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x70, 0x22, 0x8a, 0x01,
	0x0a, 0x0b, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x16, 0x0a,
	0x06, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x31, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76,
	0x31, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x2e, 0x55, 0x73,
	0x65, 0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x1a, 0x30, 0x0a, 0x04, 0x55, 0x73, 0x65, 0x72,
	0x12, 0x0e, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x49, 0x44,
	0x12, 0x18, 0x0a, 0x07, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x32, 0x69, 0x0a, 0x04, 0x41, 0x75,
	0x74, 0x68, 0x12, 0x61, 0x0a, 0x06, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x12, 0x1a, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x52, 0x65, 0x70,
	0x6c, 0x79, 0x22, 0x21, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x3a, 0x0b, 0x76, 0x65, 0x72, 0x69,
	0x66, 0x79, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x22, 0x0c, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x42, 0x23, 0x0a, 0x0b, 0x61, 0x70, 0x69, 0x2e, 0x61, 0x75, 0x74,
	0x68, 0x2e, 0x76, 0x31, 0x50, 0x01, 0x5a, 0x12, 0x73, 0x73, 0x6f, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x75, 0x74, 0x68, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_auth_v1_auth_proto_rawDescOnce sync.Once
	file_auth_v1_auth_proto_rawDescData = file_auth_v1_auth_proto_rawDesc
)

func file_auth_v1_auth_proto_rawDescGZIP() []byte {
	file_auth_v1_auth_proto_rawDescOnce.Do(func() {
		file_auth_v1_auth_proto_rawDescData = protoimpl.X.CompressGZIP(file_auth_v1_auth_proto_rawDescData)
	})
	return file_auth_v1_auth_proto_rawDescData
}

var file_auth_v1_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_auth_v1_auth_proto_goTypes = []interface{}{
	(*VerifyRequest)(nil),            // 0: api.auth.v1.VerifyRequest
	(*VerifyReply)(nil),              // 1: api.auth.v1.VerifyReply
	(*VerifyRequest_VerifyBody)(nil), // 2: api.auth.v1.VerifyRequest.VerifyBody
	(*VerifyReply_User)(nil),         // 3: api.auth.v1.VerifyReply.User
}
var file_auth_v1_auth_proto_depIdxs = []int32{
	2, // 0: api.auth.v1.VerifyRequest.verify_body:type_name -> api.auth.v1.VerifyRequest.VerifyBody
	3, // 1: api.auth.v1.VerifyReply.user:type_name -> api.auth.v1.VerifyReply.User
	0, // 2: api.auth.v1.Auth.Verify:input_type -> api.auth.v1.VerifyRequest
	1, // 3: api.auth.v1.Auth.Verify:output_type -> api.auth.v1.VerifyReply
	3, // [3:4] is the sub-list for method output_type
	2, // [2:3] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_auth_v1_auth_proto_init() }
func file_auth_v1_auth_proto_init() {
	if File_auth_v1_auth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_auth_v1_auth_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_v1_auth_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_v1_auth_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyRequest_VerifyBody); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_v1_auth_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VerifyReply_User); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_auth_v1_auth_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_auth_v1_auth_proto_goTypes,
		DependencyIndexes: file_auth_v1_auth_proto_depIdxs,
		MessageInfos:      file_auth_v1_auth_proto_msgTypes,
	}.Build()
	File_auth_v1_auth_proto = out.File
	file_auth_v1_auth_proto_rawDesc = nil
	file_auth_v1_auth_proto_goTypes = nil
	file_auth_v1_auth_proto_depIdxs = nil
}
