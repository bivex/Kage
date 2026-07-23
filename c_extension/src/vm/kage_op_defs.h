/**
 * Kage Security Extension — Internal Opcode Definitions
 */

#ifndef KAGE_OP_DEFS_H
#define KAGE_OP_DEFS_H

#include <zend_vm_opcodes.h>

/* Custom Aliases for Kage Protection */
#define KAGE_OP_CARRIER      ZEND_NOP
#define KAGE_OP_DISPATCHER   ZEND_USER_OPCODE_DISPATCH

#endif /* KAGE_OP_DEFS_H */
