package server
import "crypto/sha256"
import _ "embed"
import "encoding/base64"
import "encoding/hex"
import "golang.org/x/net/dns/dnsmessage"
import "io"
import "net"
import "net/http"
import "net/http/httptest"
import "net/url"
import "strings"
import "testing"
import "time"

//go:embed sample.txt
var sample string

func TestServer( tester * testing.T ) {
	var err error
	var server * httptest.Server
	server = httptest.NewServer( & Server{
		Delays : time.Minute ,
		Header : "X-RemoteAddr" ,
		Tokens : [ ][ 32 ]byte{
			sha256.Sum256( [ ]byte( "password" ) ) ,
		} ,
	} )
	var locate * url.URL
	locate , err = url.Parse( server.URL )
	if err != nil {
		tester.Fatal( err )
		return
	}
	// Test resolver
	var respon * http.Response
	respon , err = http.DefaultClient.Do( & http.Request{
		Method : http.MethodGet ,
		URL : & url.URL{
			Scheme : "http" ,
			User : url.UserPassword( "" , "password" ) ,
			Host : locate.Host ,
			Path : "/" ,
			RawQuery : url.Values( map[ string ][ ]string{
				"c" : [ ]string{
					"r" ,
				} ,
				"d" : [ ]string{
					"1MgBIAABAAAAAAABB2V4YW1wbGUDY29tAAAcAAEAACkE0AAAAAAADAAKAAjJR-rMVCEIuA" ,
				} ,
			} ).Encode( ) ,
		} ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	defer respon.Body.Close( )
	if respon.StatusCode != http.StatusOK {
		b , _ := io.ReadAll( respon.Body )
		println( string( b ) )
		tester.Fatal( respon.Status )
		return
	}
	var buffer [ ]byte
	buffer , err = io.ReadAll( respon.Body )
	if err != nil {
		tester.Fatal( err )
		return
	}
	err = respon.Body.Close( )
	if err != nil {
		tester.Fatal( err )
		return
	}
	var result * dnsmessage.Message = & dnsmessage.Message{ }
	err = result.Unpack( buffer )
	if err != nil {
		tester.Fatal( err )
		return
	}
	if len( result.Answers ) == 0 {
		tester.Fatal( result )
		return
	}
	// Test packet injection
	var listen net.PacketConn
	listen , err = net.ListenPacket( "ip:6" , "::1" )
	if err != nil {
		tester.Fatal( err )
		return
	}
	defer listen.Close( )
	var splits [ ]string
	splits = strings.Split( sample , "\n" )
	for ; len( splits ) > 0 ; splits = splits[ 1 : ] {
		var packet [ ]byte
		packet , err = hex.DecodeString( strings.TrimSpace( splits[ 0 ] ) )
		if err != nil {
			break
		}
		var respon * http.Response
		respon , err = http.DefaultClient.Do( & http.Request{
			Method : http.MethodGet ,
			URL : & url.URL{
				Scheme : "http" ,
				User : url.UserPassword( "" , "password" ) ,
				Host : locate.Host ,
				Path : "/" ,
				RawQuery : url.Values( map[ string ][ ]string{
					"c" : [ ]string{
						"i" ,
					} ,
					"d" : [ ]string{
						base64.RawURLEncoding.EncodeToString( packet ) ,
					} ,
				} ).Encode( ) ,
			} ,
			Header : map[ string ][ ]string{
				"X-RemoteAddr" : [ ]string{
					"2000::" ,
				} ,
			} ,
		} )
		if err != nil {
			tester.Fatal( err )
			return
		}
		err = respon.Body.Close( )
		if err != nil {
			tester.Fatal( err )
			return
		}
		if respon.StatusCode != http.StatusOK {
			tester.Fatal( respon.Status )
			return
		}
		var remote net.Addr
		_ , remote , err = listen.ReadFrom( make( [ ]byte , 65535 , 65535 ) )
		if err != nil {
			tester.Fatal( err )
			return
		}
		if remote.String( ) != "2000::" {
			tester.Fatal( remote )
			return
		}
	}
	// Test invalid
	for ; len( splits ) > 0 ; splits = splits[ 1 : ] {
		var respon * http.Response
		var packet [ ]byte
		packet , err = hex.DecodeString( strings.TrimSpace( splits[ 0 ] ) )
		if err == nil {
			respon , err = http.DefaultClient.Do( & http.Request{
				Method : http.MethodGet ,
				URL : & url.URL{
					Scheme : "http" ,
					User : url.UserPassword( "" , "password" ) ,
					Host : locate.Host ,
					Path : "/" ,
					RawQuery : url.Values( map[ string ][ ]string{
						"c" : [ ]string{
							"i" ,
						} ,
						"d" : [ ]string{
							base64.RawURLEncoding.EncodeToString( packet ) ,
						} ,
					} ).Encode( ) ,
				} ,
				Header : map[ string ][ ]string{
					"X-RemoteAddr" : [ ]string{
						"2000::" ,
					} ,
				} ,
			} )
		} else {
			respon , err = http.DefaultClient.Do( & http.Request{
				Method : http.MethodGet ,
				URL : & url.URL{
					Scheme : "http" ,
					User : url.UserPassword( "" , "password" ) ,
					Host : locate.Host ,
					Path : "/" ,
					RawQuery : splits[ 0 ] ,
				} ,
			} )
		}
		if err != nil {
			tester.Fatal( err )
			return
		}
		err = respon.Body.Close( )
		if err != nil {
			tester.Fatal( err )
			return
		}
		if respon.StatusCode == http.StatusOK {
			tester.Fatal( splits[ 0 ] )
			return
		}
	}
	err = listen.Close( )
	if err != nil {
		tester.Fatal( err )
		return
	}
	// Check auth
	respon , err = http.DefaultClient.Do( & http.Request{
		Method : http.MethodGet ,
		URL : & url.URL{
			Scheme : "http" ,
			Host : locate.Host ,
			Path : "/" ,
			RawQuery : url.Values( map[ string ][ ]string{
				"c" : [ ]string{
					"r" ,
				} ,
				"d" : [ ]string{
					"1MgBIAABAAAAAAABB2V4YW1wbGUDY29tAAAcAAEAACkE0AAAAAAADAAKAAjJR-rMVCEIuA" ,
				} ,
			} ).Encode( ) ,
		} ,
	} )
	if err != nil {
		tester.Fatal( err )
		return
	}
	err = respon.Body.Close( )
	if err != nil {
		tester.Fatal( err )
		return
	}
	if respon.StatusCode != http.StatusUnauthorized {
		tester.Fatal( respon.Status )
		return
	}
	// Test rate limit
	var offset int
	for offset = 0 ; offset < 60 ; offset += 1 {
		var respon * http.Response
		respon , err = http.DefaultClient.Do( & http.Request{
			Method : http.MethodGet ,
			URL : & url.URL{
				Scheme : "http" ,
				User : url.UserPassword( "" , "password" ) ,
				Host : locate.Host ,
				Path : "/" ,
				RawQuery : url.Values( map[ string ][ ]string{
					"c" : [ ]string{
						"r" ,
					} ,
					"d" : [ ]string{
						"1MgBIAABAAAAAAABB2V4YW1wbGUDY29tAAAcAAEAACkE0AAAAAAADAAKAAjJR-rMVCEIuA" ,
					} ,
				} ).Encode( ) ,
			} ,
		} )
		if err != nil {
			tester.Fatal( err )
			return
		}
		err = respon.Body.Close( )
		if err != nil {
			tester.Fatal( err )
			return
		}
		switch respon.StatusCode {
			case http.StatusOK :
			case http.StatusTooManyRequests :
				if offset < 30 {
					tester.Fatal( respon.Status )
				}
				return
			default :
				tester.Fatal( respon.Status )
				return
		}
	}
	tester.Fatal( "no rate limit" )
	return
}
