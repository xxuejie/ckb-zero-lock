#define CWHR_DEBUG(...)
#include "witness_args_handwritten_reader.h"

#define BUF_SIZE 32768

#define ERROR_NO_LOCK -60

int cwhr_rust_read_witness_lock(size_t index, size_t source,
                                cwhr_data_accessor_f accessor, void *context) {
  uint8_t buf[BUF_SIZE];
  cwhr_cursor_t cursor;
  int ret = cwhr_cursor_initialize(
      &cursor, cwhr_witness_loader_create(index, source), buf, BUF_SIZE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  cwhr_witness_args_reader_t reader;
  ret = cwhr_witness_args_reader_create(&reader, &cursor);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = cwhr_witness_args_reader_verify(&reader, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (!cwhr_witness_args_reader_has_lock(&reader)) {
    return ERROR_NO_LOCK;
  }
  cwhr_bytes_reader_t lock;
  ret = cwhr_witness_args_reader_lock(&reader, &lock);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  return cwhr_bytes_reader_read(&lock, accessor, context);
}
