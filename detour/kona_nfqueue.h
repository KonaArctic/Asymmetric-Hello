#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct kona_nfqueue { };

// Opens NFQueue by number.
struct kona_nfqueue * kona_nfqueue_create( uint16_t );

// Read next packet, buffer must be 64KiB.
// Returns zero on error.
size_t kona_nfqueue_read( struct kona_nfqueue * , uint8_t * );

// Send verdict: true to accept, false to drop.
// Returns false on error.
bool kona_nfqueue_verdict( struct kona_nfqueue * , bool );

// Frees resources associated with queue.
// Returns false on error.
bool kona_nfqueue_destroy( struct kona_nfqueue * );

