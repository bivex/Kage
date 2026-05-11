/**
 * Kage Extension — Virtual Opcode Mapping
 * Phase 3.1: Bytecode Transformation
 */

 #ifndef PHP_KAGE_OPCODE_MAP_H
 #define PHP_KAGE_OPCODE_MAP_H
 
 #include <stdint.h>
 #include <zend_execute.h>
 
 #ifdef __cplusplus
 extern "C" {
 #endif

/* Forward declarations */
struct _zend_op_array;
typedef struct _zend_op_array zend_op_array;
struct kage_context_s;
typedef struct kage_context_s kage_context;

/**
 * Initialize opcode mapping tables.
 */
int kage_opcode_map_init(kage_context *ctx);

/**
 * Shutdown cleanup.
 */
void kage_opcode_map_shutdown(kage_context *ctx);

/**
 * map real opcode → virtual
 */
unsigned char kage_map_opcode(kage_context *ctx, unsigned char real_opcode);

/**
 * reverse map virtual → real
 */
unsigned char kage_unmap_opcode(kage_context *ctx, unsigned char virtual_opcode);
 
/**
 * Seed-based unmapping for Dynamic ISA (Phase 6)
 */
void kage_build_map_seeded(unsigned char *map, unsigned char *reverse, uint32_t seed);
unsigned char kage_unmap_opcode_seeded(unsigned char virtual_opcode, uint32_t seed);
void kage_map_oparray_seeded(zend_op_array *op_array, uint32_t seed);
 
/**
 * Transform entire op_array by replacing opcodes with virtual mappings.
 */
void kage_map_oparray(kage_context *ctx, zend_op_array *op_array);

#ifdef __cplusplus
}
#endif

#endif /* PHP_KAGE_OPCODE_MAP_H */
