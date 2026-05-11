/**
 * Kage Extension — Virtual Opcode Mapping
 * Phase 3.1: Bytecode Transformation
 */

 #ifndef PHP_KAGE_OPCODE_MAP_H
 #define PHP_KAGE_OPCODE_MAP_H
 
 #include <stdint.h>
 #include <zend_execute.h>  // for user_opcode_handler_t
 
 #ifdef __cplusplus
 extern "C" {
 #endif

/* Forward declarations */
struct _zend_op_array;
typedef struct _zend_op_array zend_op_array;

/* Global mapping tables (defined in kage_opcode_map.c) */
extern unsigned char g_kage_opcode_map[256];
extern unsigned char g_kage_reverse_map[256];

/**
 * Initialize opcode mapping tables.
 */
int kage_opcode_map_init(void);

/**
 * Shutdown cleanup.
 */
void kage_opcode_map_shutdown(void);

/**
 * Inline: map real opcode → virtual
 */
static inline unsigned char kage_map_opcode(unsigned char real_opcode) {
    return g_kage_opcode_map[real_opcode];
}

   /**
    * Inline: reverse map virtual → real
    */
   static inline unsigned char kage_unmap_opcode(unsigned char virtual_opcode) {
       return g_kage_reverse_map[virtual_opcode];
   }
 
    /**
    * Seed-based unmapping for Dynamic ISA (Phase 6)
    */
   void kage_build_map_seeded(unsigned char *map, unsigned char *reverse, uint32_t seed);
   unsigned char kage_unmap_opcode_seeded(unsigned char virtual_opcode, uint32_t seed);
   void kage_map_oparray_seeded(zend_op_array *op_array, uint32_t seed);
 
   /**
    * Transform entire op_array by replacing opcodes with virtual mappings.
    */
  void kage_map_oparray(zend_op_array *op_array);



#ifdef __cplusplus
}
#endif

#endif /* PHP_KAGE_OPCODE_MAP_H */
