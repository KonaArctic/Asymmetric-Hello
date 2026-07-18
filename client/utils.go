package client
import "net/netip"
import "sync"

type waitFirst struct{
	finish chan error
	syonce sync.Once
}

func ( self * waitFirst )initial( ) {
	self.syonce.Do( func( ){
		self.finish = make( chan error , 0 )
	} )
}

func ( self * waitFirst )Do( action func( )error ) {
	self.initial( )
	var err error
	err = action( )
	if err != nil {
		defer func( ){
			_ = recover( )
		}( )
		self.finish <- err
	}
}

func ( self * waitFirst )Wait( )error {
	self.initial( )
	defer close( self.finish )
	return <- self.finish
}

func findPrefix( prefix map[ netip.Prefix ]any , ipaddr netip.Addr )bool {
	var offset int
	for offset = 48 ; offset >= 0 ; offset -= 1 {
		var ok bool
		_ , ok = prefix[ netip.PrefixFrom( ipaddr , offset ).Masked( ) ]
		if ok {
			return true
		}
	}
	return false
}
