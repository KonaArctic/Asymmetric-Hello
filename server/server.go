package server
import "context"
import "crypto/sha256"
import "encoding/base64"
import "fmt"
import "github.com/KonaArctic/Asymmetric-Hello/detour"
import "io"
import "net"
import "net/http"
import "net/netip"
import "net/url"
import "os"
import "slices"
import "sync"
import "time"

// Injection server
type Server struct{
	// Minimum delay between requests, averaged over one hour
	Delays time.Duration
	// Trust this HTTP header for client IP Address
	Header string
	// Upstream DNS resolver
	Resolv netip.AddrPort
	// Shared secrets for authentication
	Tokens [ ][ 32 ]byte
	errors error
	locker chan any
	record map[ string ]struct{
		number uint
		period time.Time
	}
	writer io.WriteCloser
	syonce sync.Once
}

func ( self * Server )initial( )error {
	self.syonce.Do( func( ){
		self.locker = make( chan any , 1 )
		self.record = map[ string ]struct{
			number uint
			period time.Time
		}{ }
		if ! self.Resolv.IsValid( ) {
			_ , _ = ( & net.Resolver{
				PreferGo : true ,
				Dial : func( _ context.Context , _ string , address string )( net.Conn , error ){
					self.Resolv , self.errors = netip.ParseAddrPort( address )
					return nil , io.EOF
				} ,
			} ).LookupNetIP( context.Background( ) , "ip6" , "example.com" )
		}
		if self.errors != nil {
			return
		}
		self.writer , self.errors = detour.New( [ ]detour.Filter{ } )
		if self.errors != nil {
			return
		}
	} )
	return self.errors
}

func ( self * Server )ServeHTTP( respon http.ResponseWriter , reques * http.Request ) {
	var err error
	var ok bool
	_ = reques.Write( os.Stdout )
	respon.Header( )[ "Cache-Control" ] = [ ]string{
		"no-store" ,
	}
	err = self.initial( )
	if err != nil {
		http.Error( respon , err.Error( ) , http.StatusInternalServerError )
		return
	}
	var values url.Values
	values = reques.URL.Query( )
	// Check auths
	var passwd string
	_ , passwd , ok = reques.BasicAuth( )
	if ! ok {
		// In case your front does not allow authentication
		passwd = values.Get( "p" )
		if passwd == "" {
			respon.Header( )[ "WWW-Authenticate" ] = [ ]string{
				"Basic, charset=\"UTF-8\"" ,
			}
			http.Error( respon , http.StatusText( http.StatusUnauthorized ) , http.StatusUnauthorized )
			return
		}
	}
	var digest [ 32 ]byte
	digest = sha256.Sum256( [ ]byte( passwd ) )
	if ! slices.Contains( self.Tokens , digest ) {
		respon.Header( )[ "WWW-Authenticate" ] = [ ]string{
			"Basic, charset=\"UTF-8\"" ,
		}
		http.Error( respon , http.StatusText( http.StatusUnauthorized ) , http.StatusUnauthorized )
		return
	}
	// Check rate limit
	var record struct{
		number uint
		period time.Time
	}
	self.locker <- true
	record , ok = self.record[ passwd ]
	if ! ok {
		record.period = time.Now( ).Add( time.Hour )
	} else {
		var period time.Time
		period = time.Now( )
		if period.After( record.period ) {
			record.number = 0
			record.period = period.Add( time.Hour )
		} else {
			if record.number >= uint( time.Hour / self.Delays ) {
				<- self.locker
				respon.Header( )[ "Retry-After" ] = [ ]string{
					record.period.Format( http.TimeFormat ) ,
				}
				http.Error( respon , "Try again later." , http.StatusTooManyRequests )
				return
			} else {
				record.number += 1
			}
		}
	}
	self.record[ passwd ] = record
	<- self.locker
	switch reques.Method {
		case http.MethodHead :
			respon.WriteHeader( http.StatusOK )
			return
		case http.MethodGet :
		default :
			http.Error( respon , http.StatusText( http.StatusNotImplemented ) , http.StatusNotImplemented )
			return
	}
	var encode string
	encode = values.Get( "d" )
	if encode == "" {
		http.Error( respon , "Missing parameter." , http.StatusBadRequest )
		return
	}
	var buffer [ ]byte
	buffer , err = base64.RawURLEncoding.DecodeString( encode )
	if err != nil {
		http.Error( respon , "Invalid parameter." , http.StatusBadRequest )
		return
	}
	switch values.Get( "c" ) {
		// DNS
		case "r" :
			var stream net.Conn
			stream , err = net.Dial( "udp" , self.Resolv.String( ) )
			if err != nil {
				http.Error( respon , err.Error( ) , http.StatusInternalServerError )
				return
			}
			defer stream.Close( )
			for _ , _ = range make( [ ]any , 5 , 5 ) {
				_ , err = stream.Write( buffer )
				if err != nil {
					http.Error( respon , err.Error( ) , http.StatusInternalServerError )
					return
				}
				err = stream.SetReadDeadline( time.Now( ).Add( time.Second ) )
				if err != nil {
					http.Error( respon , err.Error( ) , http.StatusInternalServerError )
					return
				}
				var buffer [ ]byte = make( [ ]byte , 0 , 65535 )
				var length int
				length , err = stream.Read( buffer[ : cap( buffer ) ] )
				buffer = buffer[ : length ]
				if err == nil {
					err = stream.Close( )
					if err != nil {
						http.Error( respon , err.Error( ) , http.StatusInternalServerError )
						return
					}
					respon.WriteHeader( http.StatusOK )
					_ , _ = respon.Write( buffer )
					return
				}
			}
			http.Error( respon , err.Error( ) , http.StatusInternalServerError )
			return
		// Inject
		case "i" :
			var remote string
			if self.Header != "" {
				remote = reques.Header.Get( self.Header )
				if remote == "" {
					_ , _ = fmt.Fprintln( os.Stderr , "Header `" + self.Header + "` not found." )
					_ , _ = fmt.Fprintln( os.Stderr , "This probably means your network or firewall is incorrectly configured!" )
					http.Error( respon , "" , http.StatusInternalServerError )
					return
				}
			} else {
				remote , _  , err = net.SplitHostPort( reques.RemoteAddr )
				if err != nil {
					http.Error( respon , err.Error( ) , http.StatusInternalServerError )
					return
				}
			}
			if ! validpacket( remote , buffer ) {
				http.Error( respon , "Packet not acceptable." , http.StatusForbidden )
				return
			}
			_ , err = self.writer.Write( buffer )
			if err != nil {
				http.Error( respon , err.Error( ) , http.StatusInternalServerError )
				return
			}
			return
		default :
			http.Error( respon , "Missing parameter." , http.StatusBadRequest )
			return
	}
}
