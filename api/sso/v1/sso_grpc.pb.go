// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.9
// source: sso/v1/sso.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SSO_UserList_FullMethodName = "/api.sso.v1.SSO/UserList"
)

// SSOClient is the client API for SSO service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SSOClient interface {
	UserList(ctx context.Context, in *UserListRequest, opts ...grpc.CallOption) (*UserListReply, error)
}

type sSOClient struct {
	cc grpc.ClientConnInterface
}

func NewSSOClient(cc grpc.ClientConnInterface) SSOClient {
	return &sSOClient{cc}
}

func (c *sSOClient) UserList(ctx context.Context, in *UserListRequest, opts ...grpc.CallOption) (*UserListReply, error) {
	out := new(UserListReply)
	err := c.cc.Invoke(ctx, SSO_UserList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SSOServer is the server API for SSO service.
// All implementations must embed UnimplementedSSOServer
// for forward compatibility
type SSOServer interface {
	UserList(context.Context, *UserListRequest) (*UserListReply, error)
	mustEmbedUnimplementedSSOServer()
}

// UnimplementedSSOServer must be embedded to have forward compatible implementations.
type UnimplementedSSOServer struct {
}

func (UnimplementedSSOServer) UserList(context.Context, *UserListRequest) (*UserListReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UserList not implemented")
}
func (UnimplementedSSOServer) mustEmbedUnimplementedSSOServer() {}

// UnsafeSSOServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SSOServer will
// result in compilation errors.
type UnsafeSSOServer interface {
	mustEmbedUnimplementedSSOServer()
}

func RegisterSSOServer(s grpc.ServiceRegistrar, srv SSOServer) {
	s.RegisterService(&SSO_ServiceDesc, srv)
}

func _SSO_UserList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).UserList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_UserList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).UserList(ctx, req.(*UserListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SSO_ServiceDesc is the grpc.ServiceDesc for SSO service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SSO_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.sso.v1.SSO",
	HandlerType: (*SSOServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UserList",
			Handler:    _SSO_UserList_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "sso/v1/sso.proto",
}
