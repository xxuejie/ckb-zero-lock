#define CWHR_DEBUG(...)
#include "witness_args_handwritten_reader.h"

#define BUF_SIZE 32768

typedef int (*cwhr_rust_bytes_meta_accessor_f)(int present, uint32_t length,
                                               void *context);

typedef struct {
  void *context;

  cwhr_rust_bytes_meta_accessor_f lock_meta_accessor;
  cwhr_data_accessor_f lock_data_accessor;

  cwhr_rust_bytes_meta_accessor_f input_type_meta_accessor;
  cwhr_data_accessor_f input_type_data_accessor;

  cwhr_rust_bytes_meta_accessor_f output_type_meta_accessor;
  cwhr_data_accessor_f output_type_data_accessor;
} cwhr_rust_accessors;

int cwhr_rust_read_witness(size_t index, size_t source,
                           const cwhr_rust_accessors *accessors) {
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

  if (cwhr_witness_args_reader_has_lock(&reader)) {
    cwhr_bytes_reader_t lock;
    ret = cwhr_witness_args_reader_lock(&reader, &lock);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint32_t length = cwhr_bytes_reader_length(&lock);
    if (accessors->lock_meta_accessor != NULL) {
      ret = accessors->lock_meta_accessor(1, length, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    if (accessors->lock_data_accessor != NULL) {
      ret = cwhr_bytes_reader_read(&lock, accessors->lock_data_accessor,
                                   accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  } else {
    if (accessors->lock_meta_accessor != NULL) {
      ret = accessors->lock_meta_accessor(0, 0, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  }

  if (cwhr_witness_args_reader_has_input_type(&reader)) {
    cwhr_bytes_reader_t input_type;
    ret = cwhr_witness_args_reader_input_type(&reader, &input_type);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint32_t length = cwhr_bytes_reader_length(&input_type);
    if (accessors->input_type_meta_accessor != NULL) {
      ret = accessors->input_type_meta_accessor(1, length, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    if (accessors->input_type_data_accessor != NULL) {
      ret = cwhr_bytes_reader_read(
          &input_type, accessors->input_type_data_accessor, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  } else {
    if (accessors->input_type_meta_accessor != NULL) {
      ret = accessors->input_type_meta_accessor(0, 0, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  }

  if (cwhr_witness_args_reader_has_output_type(&reader)) {
    cwhr_bytes_reader_t output_type;
    ret = cwhr_witness_args_reader_output_type(&reader, &output_type);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint32_t length = cwhr_bytes_reader_length(&output_type);
    if (accessors->output_type_meta_accessor != NULL) {
      ret = accessors->output_type_meta_accessor(1, length, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
    if (accessors->output_type_data_accessor != NULL) {
      ret = cwhr_bytes_reader_read(&output_type,
                                   accessors->output_type_data_accessor,
                                   accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  } else {
    if (accessors->output_type_meta_accessor != NULL) {
      ret = accessors->output_type_meta_accessor(0, 0, accessors->context);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
    }
  }

  return CKB_SUCCESS;
}
