/**
 * Kage AST Converter — Bytecode Generation
 */

#include "ast.h"
#include "vm.h"
#include "kage_memory.h"

/* Internal constants */
#define KAGE_PARSER_DEFAULT_STACK_SIZE 100

/* Forward declarations */
static int add_instruction(kage_vm_state *state, kage_opcode opcode, zval *operand);
static int convert_string_node(kage_ast_node *node, kage_vm_state *state);
static int convert_encrypt_node(kage_ast_node *node, kage_vm_state *state);
static int convert_decrypt_node(kage_ast_node *node, kage_vm_state *state);
static int convert_program_node(kage_ast_node *node, kage_vm_state *state);
static int ast_to_bytecode(kage_ast_node *node, kage_vm_state *state);

/**
 * Adds an instruction to the VM state with bounds checking.
 */
static int add_instruction(kage_vm_state *state, kage_opcode opcode, zval *operand) {
    if (state != NULL && state->instructions != NULL) {
        if (state->instruction_count < KAGE_PARSER_DEFAULT_STACK_SIZE) {
            kage_instruction *instr = &state->instructions[state->instruction_count++];
            instr->opcode = opcode;
            if (operand != NULL) {
                ZVAL_COPY(&instr->operand, operand);
            } else {
                ZVAL_NULL(&instr->operand);
            }
            return SUCCESS;
        } else {
            zend_error(E_WARNING, "Kage AST: Too many instructions generated");
        }
    }
    return FAILURE;
}

/**
 * Converts a string AST node to bytecode.
 */
static int convert_string_node(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) return FAILURE;
    return add_instruction(state, KAGE_OP_PUSH, &node->value);
}

/**
 * Converts an encrypt AST node to bytecode.
 */
static int convert_encrypt_node(kage_ast_node *node, kage_vm_state *state) {
    if (node != NULL && state != NULL && node->left != NULL) {
        if (ast_to_bytecode(node->left, state) == SUCCESS) {
            return add_instruction(state, KAGE_OP_ENCRYPT, NULL);
        }
    }
    return FAILURE;
}

/**
 * Converts a decrypt AST node to bytecode.
 */
static int convert_decrypt_node(kage_ast_node *node, kage_vm_state *state) {
    if (node != NULL && state != NULL && node->left != NULL) {
        if (ast_to_bytecode(node->left, state) == SUCCESS) {
            return add_instruction(state, KAGE_OP_DECRYPT, NULL);
        }
    }
    return FAILURE;
}

/**
 * Converts a program AST node to bytecode.
 */
static int convert_program_node(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) return FAILURE;
    kage_ast_node *stmt = node->next;
    while (stmt != NULL) {
        if (ast_to_bytecode(stmt, state) != SUCCESS) return FAILURE;
        stmt = stmt->next;
    }
    return SUCCESS;
}

/**
 * Converts an AST node to bytecode instructions.
 */
static int ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) return FAILURE;
    switch (node->type) {
        case KAGE_AST_STRING:  return convert_string_node(node, state);
        case KAGE_AST_ENCRYPT: return convert_encrypt_node(node, state);
        case KAGE_AST_DECRYPT: return convert_decrypt_node(node, state);
        case KAGE_AST_PROGRAM: return convert_program_node(node, state);
        default:
            zend_error(E_WARNING, "Kage AST: Unknown AST node type: %d", node->type);
            return FAILURE;
    }
}

/**
 * Converts an AST to bytecode instructions (Entry Point).
 */
PHPAPI int kage_ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) {
        zend_error(E_WARNING, "Kage AST: Invalid parameters for bytecode conversion");
        return FAILURE;
    }

    state->instructions = (kage_instruction *)KAGE_ALLOC(KAGE_PARSER_DEFAULT_STACK_SIZE * sizeof(kage_instruction));
    if (state->instructions == NULL) {
        zend_error(E_WARNING, "Kage AST: Failed to allocate instruction memory");
        return FAILURE;
    }

    state->instruction_count = 0;
    int result = ast_to_bytecode(node, state);
    if (result != SUCCESS) {
        efree(state->instructions);
        state->instructions = NULL;
        state->instruction_count = 0;
    }
    return result;
}
