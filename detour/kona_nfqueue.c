#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kona_nfqueue.h"

struct kona_nfqueue_packet{
  int packid;
  int length;
  uint8_t * buffer;
};

struct kona_nfqueue_object {
  uint16_t number;
  struct nfq_handle * handle;
  int receive;
  struct nfq_q_handle * queue;
  struct kona_nfqueue_packet packet;
};

static inline struct kona_nfqueue_object * kona_nfqueue_concrete( struct kona_nfqueue * object ) {
  return ( struct kona_nfqueue_object * ) object;
}

static int kona_nfqueue_callback( struct nfq_q_handle * qh , struct nfgenmsg * nfmsg , struct nfq_data * nfad , struct kona_nfqueue_packet * packet ) {
  packet->length = nfq_get_payload( nfad , & packet->buffer );
  if ( packet->length < 0 )
    return -2;
  struct nfqnl_msg_packet_hdr * header;
  header = nfq_get_msg_packet_hdr( nfad );
  if ( ! header )
    return -3;
  packet->packid = ntohl( header->packet_id );
  return 0;
};

// Frees resources associated with queue.
// Returns false on error.
bool kona_nfqueue_destroy( struct kona_nfqueue * object ) {
  int err;
  nfq_destroy_queue( kona_nfqueue_concrete( object )->queue );
  err = nfq_close( kona_nfqueue_concrete( object )->handle );
  free( object );
  return err == 0;
}

// Opens NFQueue by number.
struct kona_nfqueue * kona_nfqueue_create( uint16_t number ) {
  int err;
  struct kona_nfqueue_object * object;
  object = malloc( sizeof( struct kona_nfqueue_object ) );
  if ( ! object )
    return NULL;
  object->handle = nfq_open( );
  if ( ! object->handle ) {
    free( object );
    return NULL;
  }
  object->receive = nfq_fd( object->handle );
  if ( ! object->receive ) {
    nfq_close( object->handle );
    free( object );
    return NULL;
  }
  object->queue = nfq_create_queue( object->handle , number , ( int ( * )( struct nfq_q_handle * , struct nfgenmsg * , struct nfq_data * , void * ) ) & kona_nfqueue_callback , ( void * ) & object->packet );
  if ( ! object->queue ) {
    nfq_close( object->handle );
    free( object );
    return NULL;
  }
  err = nfq_set_mode( object->queue , NFQNL_COPY_PACKET , 65535 );
  if ( err < 0 ) {
    kona_nfqueue_destroy( ( struct kona_nfqueue * ) object );
    return NULL;
  }
  err = nfq_set_queue_flags( object->queue , NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN );
  if ( err < 0 ) {
    kona_nfqueue_destroy( ( struct kona_nfqueue * ) object );
    return NULL;
  }
  // TODO Handle truncated packets
  // https://manpages.debian.org/trixie/libnetfilter-queue-doc/nfq_set_queue_flags.3.en.html#int_nfq_set_queue_flags_(struct_nfq_q_handle_*_qh,_uint32_t_mask,_uint32_t_flags)
  err = nfq_set_queue_flags( object->queue , NFQA_CFG_F_GSO , NFQA_CFG_F_GSO );
  if ( err < 0 ) {
    kona_nfqueue_destroy( ( struct kona_nfqueue * ) object );
    return NULL;
  }
  return ( struct kona_nfqueue * ) object;
}

// Read next packet, buffer must be 64KiB.
// Returns zero on error.
size_t kona_nfqueue_read( struct kona_nfqueue * object , uint8_t * buffer ) {
  int err;
  size_t length;
  length = recv( kona_nfqueue_concrete( object )->receive , buffer , 65535 , 0 );
  if ( length < 0 )
    return 0;
  err = nfq_handle_packet( kona_nfqueue_concrete( object )->handle , ( char * ) buffer , length );
  if ( err )
    return 0;
  // TODO Reduce memory copies
  memcpy( buffer , kona_nfqueue_concrete( object )->packet.buffer , kona_nfqueue_concrete( object )->packet.length );
  return kona_nfqueue_concrete( object )->packet.length;
}

// Send verdict: true to accept, false to drop.
// Returns false on error.
bool kona_nfqueue_verdict( struct kona_nfqueue * object , bool status ) {
  return nfq_set_verdict( kona_nfqueue_concrete( object )->queue , kona_nfqueue_concrete( object )->packet.packid , status ? NF_ACCEPT : NF_DROP , 0 , NULL ) >= 0;
}


