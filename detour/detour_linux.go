package detour
//#cgo LDFLAGS: -lnetfilter_queue
//#include "kona_nfqueue.h"
import "C"
import "crypto/rand"
import "errors"
import "golang.org/x/sys/unix"
import "io"
import "net"

func create( filter [ ]Filter )( Detour , error ) {
	var err error
	// For reasons I could not figure out sometimes injected packets are not routed correctly
	// (e.g. global unicast to loopback) so here's a workaround.
	var inface [ ]net.Interface
	inface , err = net.Interfaces( )
	if err != nil {
		return nil , err
	}
	var sockv4 [ ]int = make( [ ]int , 0 , len( inface ) )
	var sockv6 [ ]int = make( [ ]int , 0 , len( inface ) )
	for ; len( inface ) > 0 ; inface = inface[ 1 : ] {
		var socket int
		socket , err = unix.Socket( unix.AF_INET , unix.SOCK_RAW , unix.IPPROTO_RAW )
		if err != nil {
			return nil , err
		}
		err = unix.BindToDevice( socket , inface[ 0 ].Name )
		if err != nil {
			return nil , err
		}
		sockv4 = append( sockv4 , socket )
		socket , err = unix.Socket( unix.AF_INET6 , unix.SOCK_RAW , unix.IPPROTO_RAW )
		if err != nil {
			return nil , err
		}
		err = unix.BindToDevice( socket , inface[ 0 ].Name )
		if err != nil {
			return nil , err
		}
		sockv6 = append( sockv6 , socket )
	}
	if len( filter ) == 0 {
		return & detour{
			sockv4 : sockv4 ,
			sockv6 : sockv6 ,
		} , nil
	}
	var random [ ]byte = make( [ ]byte , 16 , 16 )
	_ , err = io.ReadFull( rand.Reader , random )
	if err != nil {
		return nil , err
	}
	var reader * C.struct_kona_nfqueue
	var number uint16
	for number = 1 ; ; number += 1 {	// Find spare queue number
		reader = C.kona_nfqueue_create( C.uint16_t( number ) )
		if reader != nil {
			break
		}
		if number == 65535 {
			return nil , errors.New( "kona_nfqueue_create failed" )
		}
	}
	err = nftablesCreate( filter , number , random )
	if err != nil {
		_ = C.kona_nfqueue_destroy( reader )
		return nil , err
	}
	var socket int
	for _ , socket = range append( sockv4 , sockv6 ... ) {
		err = unix.SetsockoptInt( socket , unix.SOL_SOCKET , unix.SO_MARK , int( number ) )
		if err != nil {
			_ = C.kona_nfqueue_destroy( reader )
			return nil , err
		}
	}
	return & detour{
		random : random ,
		reader : reader ,
		sockv4 : sockv4 ,
		sockv6 : sockv6 ,
	} , nil
}

type detour struct{
	random [ ]byte
	reader * C.struct_kona_nfqueue
	status int
	sockv4 [ ]int
	sockv6 [ ]int
}

func ( self * detour )Read( buffer [ ]byte )( int , error ) {
	if self.status > 0 {
		var ok bool
		ok = bool( C.kona_nfqueue_verdict( self.reader , self.status == 1 ) )
		if ! ok {
			return 0 , errors.New( "kona_nfqueue_verdict failed" )
		}
	}
	var length int
	length = int( C.kona_nfqueue_read( self.reader , ( * C.uint8_t )( & buffer[ 0 ] ) ) )
	if length == 0 {
		return 0 , errors.New( "kona_nfqueue_read failed" )
	}
	self.status = 1
	return length , nil
}

func ( self * detour )Write( buffer [ ]byte )( int , error ) {
	var err error
	if buffer[ 0 ] >> 4 == 4 {
		var socket int
		for _ , socket = range self.sockv4 {
			err = unix.Sendto( socket , buffer , 0 , & unix.SockaddrInet4{ } )
			if err != nil {
				return 0 , err
			}
		}
	} else {
		var socket int
		for _ , socket = range self.sockv6 {
			err = unix.Sendto( socket , buffer , 0 , & unix.SockaddrInet6{ } )
			switch err {
				case nil :
				case unix.EMSGSIZE :
					return 0 , ErrPacketTooBig
				default :
					return 0 , err
			}
		}
	}
	return len( buffer ) , nil
}

func ( self * detour )Discard( )error {
	self.status = 2
	return nil
}

func ( self * detour )Close( )error {
	var err error
	var socket [ ]int
	socket = append( self.sockv4 , self.sockv6 ... )
	defer func( ){
		for ; len( socket ) > 0 ; socket = socket[ 1 : ] {
			_ = unix.Close( socket[ 0 ] )
		}
	}( )
	if self.reader != nil {
		defer nftablesDestroy( self.random )
		var ok bool
		ok = bool( C.kona_nfqueue_destroy( self.reader ) )
		if ! ok {
			return errors.New( "kona_nfqueue_destroy failed" )
		}
		err = nftablesDestroy( self.random )
		if err != nil {
			return err
		}
	}
	for ; len( socket ) > 0 ; socket = socket[ 1 : ] {
		err = unix.Close( socket[ 0 ] )
		if err != nil {
			return err
		}
	}
	return nil
}
