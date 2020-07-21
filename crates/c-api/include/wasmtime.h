/**
 * @file
 *
 * Wasmtime-specific extensions to the WebAssembly C API.
 *
 * This file contains all of the Wasmtime-specific functions which will not be
 * present in other engines. The intention of this file is to augment the
 * functionality provided in `wasm.h`.
 */


#ifndef WASMTIME_API_H
#define WASMTIME_API_H

#include <wasm.h>
#include <wasi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define own

#define WASMTIME_DECLARE_OWN(name) \
  typedef struct wasmtime_##name##_t wasmtime_##name##_t; \
  \
  WASM_API_EXTERN void wasmtime_##name##_delete(own wasmtime_##name##_t*);

/**
 * \typedef wasmtime_error_t
 * \brief Convenience alias for #wasmtime_error_t
 *
 * \struct wasmtime_error_t
 * \brief Errors generated by Wasmtime.
 *
 * This opaque type represents an error that happened as part of one of the
 * functions below. Errors primarily have an error message associated with them
 * at this time, which you can acquire by calling #wasmtime_error_message.
 *
 * \fn void wasmtime_error_delete(own wasmtime_error_t *);
 * \brief Deletes an error.
 */
WASMTIME_DECLARE_OWN(error)

/**
 * \brief Returns the string description of this error.
 *
 * This will "render" the error to a string and then return the string
 * representation of the error to the caller. The `message` argument should be
 * uninitialized before this function is called and the caller is responsible
 * for deallocating it with #wasm_byte_vec_delete afterwards.
 */
WASM_API_EXTERN void wasmtime_error_message(
    const wasmtime_error_t *error,
    own wasm_name_t *message
);

/**
 * \brief Specifier for how Wasmtime will compile code, values are in
 * #wasmtime_strategy_enum
 */
typedef uint8_t wasmtime_strategy_t;

/**
 * \brief Different ways that Wasmtime can compile WebAssembly
 *
 * The default value is #WASMTIME_STRATEGY_AUTO.
 */
enum wasmtime_strategy_enum { // Strategy
  /// Wasmtime will automatically determine whether to use Cranelift or
  /// Lightbeam, and currently it will always pick Cranelift. This default may
  /// change over time though.
  WASMTIME_STRATEGY_AUTO,

  /// Indicates that Cranelift will unconditionally use Cranelift to compile
  /// WebAssembly code.
  WASMTIME_STRATEGY_CRANELIFT,

  /// Indicates that Cranelift will unconditionally use Lightbeam to compile
  /// WebAssembly code. Note that Lightbeam isn't always enabled at compile
  /// time, and if that's the case an error will be returned.
  WASMTIME_STRATEGY_LIGHTBEAM,
};

/**
 * \brief Specifier of what optimization level to use for generated JIT code.
 *
 * See #wasmtime_opt_level_enum for possible values.
 */
typedef uint8_t wasmtime_opt_level_t;

/**
 * \brief Different ways Wasmtime can optimize generated code.
 *
 * The default value is #WASMTIME_OPT_LEVEL_SPEED.
 */
enum wasmtime_opt_level_enum { // OptLevel
  /// Generated code will not be optimized at all.
  WASMTIME_OPT_LEVEL_NONE,
  /// Generated code will be optimized purely for speed.
  WASMTIME_OPT_LEVEL_SPEED,
  /// Generated code will be optimized, but some speed optimizations are
  /// disabled if they cause the generated code to be significantly larger.
  WASMTIME_OPT_LEVEL_SPEED_AND_SIZE,
};

/**
 * \brief Different ways wasmtime can enable profiling JIT code.
 *
 * See #wasmtime_profiling_strategy_enum for possible values.
 */
typedef uint8_t wasmtime_profiling_strategy_t;

/**
 * \brief Different ways to profile JIT code.
 *
 * The default is #WASMTIME_PROFILING_STRATEGY_NONE.
 */
enum wasmtime_profiling_strategy_enum { // ProfilingStrategy
  /// No profiling is enabled at runtime.
  WASMTIME_PROFILING_STRATEGY_NONE,
  /// Linux's "jitdump" support in `perf` is enabled and when Wasmtime is run
  /// under `perf` necessary calls will be made to profile generated JIT code.
  WASMTIME_PROFILING_STRATEGY_JITDUMP,
  /// Support for VTune will be enabled and the VTune runtime will be informed,
  /// at runtime, about JIT code.
  ///
  /// Note that this isn't always enabled at build time.
  WASMTIME_PROFILING_STRATEGY_VTUNE,
};

#define WASMTIME_CONFIG_PROP(ret, name, ty) \
    WASM_API_EXTERN ret wasmtime_config_##name##_set(wasm_config_t*, ty);

/**
 * \brief Configures whether DWARF debug information is constructed at runtime
 * to describe JIT code.
 *
 * This setting is `false` by default. When enabled it will attempt to inform
 * native debuggers about DWARF debugging information for JIT code to more
 * easily debug compiled WebAssembly via native debuggers. This can also
 * sometimes improve the quality of output when profiling is enabled.
 */
WASMTIME_CONFIG_PROP(void, debug_info, bool)

/**
 * \brief Enables WebAssembly code to be interrupted.
 *
 * This setting is `false` by default. When enabled it will enable getting an
 * interrupt handle via #wasmtime_interrupt_handle_new which can be used to
 * interrupt currently-executing WebAssembly code.
 */
WASMTIME_CONFIG_PROP(void, interruptable, bool)

/**
 * \brief Configures the maximum stack size, in bytes, that JIT code can use.
 *
 * This setting is 2MB by default. Configuring this setting will limit the
 * amount of native stack space that JIT code can use while it is executing. If
 * you're hitting stack overflow you can try making this setting larger, or if
 * you'd like to limit wasm programs to less stack you can also configure this.
 *
 * Note that this setting is not interpreted with 100% precision. Additionally
 * the amount of stack space that wasm takes is always relative to the first
 * invocation of wasm on the stack, so recursive calls with host frames in the
 * middle will all need to fit within this setting.
 */
WASMTIME_CONFIG_PROP(void, max_wasm_stack, size_t)

/**
 * \brief Configures whether the WebAssembly threading proposal is enabled.
 *
 * This setting is `false` by default.
 *
 * Note that threads are largely unimplemented in Wasmtime at this time.
 */
WASMTIME_CONFIG_PROP(void, wasm_threads, bool)

/**
 * \brief Configures whether the WebAssembly reference types proposal is
 * enabled.
 *
 * This setting is `false` by default.
 */
WASMTIME_CONFIG_PROP(void, wasm_reference_types, bool)

/**
 * \brief Configures whether the WebAssembly SIMD proposal is
 * enabled.
 *
 * This setting is `false` by default.
 */
WASMTIME_CONFIG_PROP(void, wasm_simd, bool)

/**
 * \brief Configures whether the WebAssembly bulk memory proposal is
 * enabled.
 *
 * This setting is `false` by default.
 */
WASMTIME_CONFIG_PROP(void, wasm_bulk_memory, bool)

/**
 * \brief Configures whether the WebAssembly multi value proposal is
 * enabled.
 *
 * This setting is `true` by default.
 */
WASMTIME_CONFIG_PROP(void, wasm_multi_value, bool)

/**
 * \brief Configures how JIT code will be compiled.
 *
 * This setting is #WASMTIME_STRATEGY_AUTO by default.
 *
 * If the compilation strategy selected could not be enabled then an error is
 * returned.
 */
WASMTIME_CONFIG_PROP(wasmtime_error_t*, strategy, wasmtime_strategy_t)

/**
 * \brief Configures whether Cranelift's debug verifier is enabled.
 *
 * This setting in `false` by default.
 *
 * When cranelift is used for compilation this enables expensive debug checks
 * within Cranelift itself to verify it's correct.
 */
WASMTIME_CONFIG_PROP(void, cranelift_debug_verifier, bool)

/**
 * \brief Configures Cranelift's optimization level for JIT code.
 *
 * This setting in #WASMTIME_OPT_LEVEL_SPEED by default.
 */
WASMTIME_CONFIG_PROP(void, cranelift_opt_level, wasmtime_opt_level_t)

/**
 * \brief Configures the profiling strategy used for JIT code.
 *
 * This setting in #WASMTIME_PROFILING_STRATEGY_NONE by default.
 */
WASMTIME_CONFIG_PROP(wasmtime_error_t*, profiler, wasmtime_profiling_strategy_t)

/**
 * \brief Configures the maximum size for memory to be considered "static"
 *
 * For more information see the Rust documentation at
 * https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Config.html#method.static_memory_maximum_size.
 */
WASMTIME_CONFIG_PROP(void, static_memory_maximum_size, uint64_t)

/**
 * \brief Configures the guard region size for "static" memory.
 *
 * For more information see the Rust documentation at
 * https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Config.html#method.static_memory_guard_size.
 */
WASMTIME_CONFIG_PROP(void, static_memory_guard_size, uint64_t)

/**
 * \brief Configures the guard region size for "dynamic" memory.
 *
 * For more information see the Rust documentation at
 * https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Config.html#method.dynamic_memory_guard_size.
 */
WASMTIME_CONFIG_PROP(void, dynamic_memory_guard_size, uint64_t)

/**
 * \brief Enables Wasmtime's cache and loads configuration from the specified
 * path.
 *
 * By default the Wasmtime compilation cache is disabled. The configuration path
 * here can be `NULL` to use the default settings, and otherwise the argument
 * here must be a file on the filesystem with TOML configuration -
 * https://bytecodealliance.github.io/wasmtime/cli-cache.html.
 *
 * An error is returned if the cache configuration could not be loaded or if the
 * cache could not be enabled.
 */
WASM_API_EXTERN wasmtime_error_t* wasmtime_config_cache_config_load(wasm_config_t*, const char*);

/**
 * \brief Converts from the text format of WebAssembly to to the binary format.
 *
 * \param wat this it the input buffer with the WebAssembly Text Format inside of
 *   it. This will be parsed and converted to the binary format.
 * \param ret if the conversion is successful, this byte vector is filled in with
 *   the WebAssembly binary format.
 *
 * \return a non-null error if parsing fails, or returns `NULL`. If parsing
 * fails then `ret` isn't touched.
 *
 * This function does not take ownership of `wat`, and the caller is expected to
 * deallocate the returned #wasmtime_error_t and #wasm_byte_vec_t.
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_wat2wasm(
    const wasm_byte_vec_t *wat,
    own wasm_byte_vec_t *ret
);

/**
 * \brief Perform garbage collection within the given store.
 *
 * Garbage collects `externref`s that are used within this store. Any
 * `externref`s that are discovered to be unreachable by other code or objects
 * will have their finalizers run.
 *
 * The `store` argument must not be NULL.
 */
WASM_API_EXTERN void wasmtime_store_gc(wasm_store_t* store);

/**
 * \typedef wasmtime_linker_t
 * \brief Convenience alias for #wasmtime_linker_t
 *
 * \struct wasmtime_linker_t
 * \brief Object used to conveniently link together and instantiate wasm
 * modules.
 *
 * This type corresponds to the `wasmtime::Linker` type in Rust. This
 * Wasmtime-specific extension is intended to make it easier to manage a set of
 * modules that link together, or to make it easier to link WebAssembly modules
 * to WASI.
 *
 * A #wasmtime_linker_t is a higher level way to instantiate a module than
 * #wasm_instance_new since it works at the "string" level of imports rather
 * than requiring 1:1 mappings.
 *
 * \fn void wasmtime_linker_delete(own wasmtime_linker_t *);
 * \brief Deletes a linker.
 */
WASMTIME_DECLARE_OWN(linker)

/**
 * \brief Creates a new linker which will link together objects in the specified
 * store.
 *
 * This function does not take ownership of the store argument, and the caller
 * is expected to delete the returned linker.
 */
WASM_API_EXTERN own wasmtime_linker_t* wasmtime_linker_new(wasm_store_t* store);

/**
 * \brief Configures whether this linker allows later definitions to shadow
 * previous definitions.
 *
 * By default this setting is `false`.
 */
WASM_API_EXTERN void wasmtime_linker_allow_shadowing(wasmtime_linker_t* linker, bool allow_shadowing);

/**
 * \brief Defines a new item in this linker.
 *
 * \param linker the linker the name is being defined in.
 * \param module the module name the item is defined under.
 * \param name the field name the item is defined under
 * \param item the item that is being defined in this linker.
 *
 * \return On success `NULL` is returned, otherwise an error is returned which
 * describes why the definition failed.
 *
 * For more information about name resolution consult the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Linker.html#name-resolution).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_define(
    wasmtime_linker_t *linker,
    const wasm_name_t *module,
    const wasm_name_t *name,
    const wasm_extern_t *item
);

/**
 * \brief Defines a WASI instance in this linker.
 *
 * \param linker the linker the name is being defined in.
 * \param instance a previously-created WASI instance.
 *
 * \return On success `NULL` is returned, otherwise an error is returned which
 * describes why the definition failed.
 *
 * For more information about name resolution consult the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Linker.html#name-resolution).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_define_wasi(
    wasmtime_linker_t *linker,
    const wasi_instance_t *instance
);

/**
 * \brief Defines an instance under the specified name in this linker.
 *
 * \param linker the linker the name is being defined in.
 * \param name the module name to define `instance` under.
 * \param instance a previously-created instance.
 *
 * \return On success `NULL` is returned, otherwise an error is returned which
 * describes why the definition failed.
 *
 * This function will take all of the exports of the `instance` provided and
 * defined them under a module called `name` with a field name as the export's
 * own name.
 *
 * For more information about name resolution consult the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Linker.html#name-resolution).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_define_instance(
    wasmtime_linker_t *linker,
    const wasm_name_t *name,
    const wasm_instance_t *instance
);

/**
 * \brief Instantiates a #wasm_module_t with the items defined in this linker.
 *
 * \param linker the linker used to instantiate the provided module.
 * \param module the module that is being instantiated.
 * \param instance the returned instance, if successful.
 * \param trap a trap returned, if the start function traps.
 *
 * \return One of three things can happen as a result of this function. First
 * the module could be successfully instantiated and returned through
 * `instance`, meaning the return value and `trap` are both set to `NULL`.
 * Second the start function may trap, meaning the return value and `instance`
 * are set to `NULL` and `trap` describes the trap that happens. Finally
 * instantiation may fail for another reason, in which case an error is returned
 * and `trap` and `instance` are set to `NULL`.
 *
 * This function will attempt to satisfy all of the imports of the `module`
 * provided with items previously defined in this linker. If any name isn't
 * defined in the linker than an error is returned. (or if the previously
 * defined item is of the wrong type).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_instantiate(
    const wasmtime_linker_t *linker,
    const wasm_module_t *module,
    own wasm_instance_t **instance,
    own wasm_trap_t **trap
);

/**
 * \brief Defines automatic instantiations of a #wasm_module_t in this linker.
 *
 * \param linker the linker the module is being added to
 * \param name the name of the module within the linker
 * \param module the module that's being instantiated
 *
 * \return An error if the module could not be instantiated or added or `NULL`
 * on success.
 *
 * This function automatically handles [Commands and
 * Reactors](https://github.com/WebAssembly/WASI/blob/master/design/application-abi.md#current-unstable-abi)
 * instantiation and initialization.
 *
 * For more information see the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Linker.html#method.module).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_module(
    const wasmtime_linker_t *linker,
    const wasm_name_t *name,
    const wasm_module_t *module
);

/**
 * \brief Acquires the "default export" of the named module in this linker.
 *
 * \param linker the linker to load from
 * \param name the name of the module to get the default export for
 * \param func where to store the extracted default function.
 *
 * \return An error is returned if the default export could not be found, or
 * `NULL` is returned and `func` is filled in otherwise.
 *
 * For more information see the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Linker.html#method.get_default).
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_get_default(
    const wasmtime_linker_t *linker,
    const wasm_name_t *name,
    own wasm_func_t **func
);

/**
 * \brief Loads an item by name from this linker.
 *
 * \param linker the linker to load from
 * \param module the name of the module to get
 * \param name the name of the field to get
 * \param item where to store the extracted item
 *
 * \return An error is returned if the item isn't defined or has more than one
 * definition, or `NULL` is returned and `item` is filled in otherwise.
 */
WASM_API_EXTERN own wasmtime_error_t* wasmtime_linker_get_one_by_name(
    const wasmtime_linker_t *linker,
    const wasm_name_t *module,
    const wasm_name_t *name,
    own wasm_extern_t **item
);

/**
 * \brief Structure used to learn about the caller of a host-defined function.
 *
 * This structure is the first argument of #wasmtime_func_callback_t and
 * wasmtime_func_callback_with_env_t. The main purpose of this structure is for
 * building a WASI-like API which can inspect the memory of the caller,
 * regardless of the caller.
 *
 * This is intended to be a temporary API extension until interface types have
 * become more prevalent. This is not intended to be supported until the end of
 * time, but it will be supported so long as WASI requires it.
 */
typedef struct wasmtime_caller_t wasmtime_caller_t;

/**
 * \brief Callback signature for #wasmtime_func_new.
 *
 * This function is the same as #wasm_func_callback_t except that its first
 * argument is a #wasmtime_caller_t which allows learning information about the
 * caller.
 */
typedef own wasm_trap_t* (*wasmtime_func_callback_t)(const wasmtime_caller_t* caller, const wasm_val_t args[], wasm_val_t results[]);

/**
 * \brief Callback signature for #wasmtime_func_new_with_env.
 *
 * This function is the same as #wasm_func_callback_with_env_t except that its
 * first argument is a #wasmtime_caller_t which allows learning information
 * about the caller.
 */
typedef own wasm_trap_t* (*wasmtime_func_callback_with_env_t)(const wasmtime_caller_t* caller, void* env, const wasm_val_t args[], wasm_val_t results[]);

/**
 * \brief Creates a new host-defined function.
 *
 * This function is the same as #wasm_func_new, except the callback has the type
 * signature #wasmtime_func_callback_t which gives a #wasmtime_caller_t as its
 * first argument.
 */
WASM_API_EXTERN own wasm_func_t* wasmtime_func_new(wasm_store_t*, const wasm_functype_t*, wasmtime_func_callback_t callback);

/**
 * \brief Creates a new host-defined function.
 *
 * This function is the same as #wasm_func_new_with_env, except the callback
 * has the type signature #wasmtime_func_callback_with_env_t which gives a
 * #wasmtime_caller_t as its first argument.
 */
WASM_API_EXTERN own wasm_func_t* wasmtime_func_new_with_env(
  wasm_store_t* store,
  const wasm_functype_t* type,
  wasmtime_func_callback_with_env_t callback,
  void* env,
  void (*finalizer)(void*)
);

/**
 * \brief Creates a new `funcref` value referencing `func`.
 *
 * Create a `funcref` value that references `func` and writes it to `funcrefp`.
 *
 * Gives ownership fo the `funcref` value written to `funcrefp`.
 *
 * Both `func` and `funcrefp` must not be NULL.
 */
WASM_API_EXTERN void wasmtime_func_as_funcref(const wasm_func_t* func, wasm_val_t* funcrefp);

/**
 * \brief Get the `wasm_func_t*` referenced by the given `funcref` value.
 *
 * Gets an owning handle to the `wasm_func_t*` that the given `funcref` value is
 * referencing. Returns NULL if the value is not a `funcref`, or if the value is
 * a null function reference.
 *
 * The `val` pointer must not be NULL.
 */
WASM_API_EXTERN own wasm_func_t* wasmtime_funcref_as_func(const wasm_val_t* val);

/**
 * \brief Loads a #wasm_extern_t from the caller's context
 *
 * This function will attempt to look up the export named `name` on the caller
 * instance provided. If it is found then the #wasm_extern_t for that is
 * returned, otherwise `NULL` is returned.
 *
 * Note that this only works for exported memories right now for WASI
 * compatibility.
 */
WASM_API_EXTERN own wasm_extern_t* wasmtime_caller_export_get(const wasmtime_caller_t* caller, const wasm_name_t* name);

/**
 * \typedef wasmtime_interrupt_handle_t
 * \brief Convenience alias for #wasmtime_interrupt_handle_t
 *
 * \struct wasmtime_interrupt_handle_t
 * \brief A handle used to interrupt executing WebAssembly code.
 *
 * This structure is an opaque handle that represents a handle to a store. This
 * handle can be used to remotely (from another thread) interrupt currently
 * executing WebAssembly code.
 *
 * This structure is safe to share from multiple threads.
 *
 * \fn void wasmtime_interrupt_handle_delete(own wasmtime_interrupt_handle_t *);
 * \brief Deletes an interrupt handle.
 */
WASMTIME_DECLARE_OWN(interrupt_handle)

/**
 * \brief Creates a new interrupt handle to interrupt executing WebAssembly from
 * the provided store.
 *
 * There are a number of caveats about how interrupt is handled in Wasmtime. For
 * more information see the [Rust
 * documentation](https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Store.html#method.interrupt_handle).
 *
 * This function returns `NULL` if the store's configuration does not have
 * interrupts enabled. See #wasmtime_config_interruptable_set.
 */
WASM_API_EXTERN own wasmtime_interrupt_handle_t *wasmtime_interrupt_handle_new(wasm_store_t *store);

/**
 * \brief Requests that WebAssembly code running in the store attached to this
 * interrupt handle is interrupted.
 *
 * For more information about interrupts see #wasmtime_interrupt_handle_new.
 *
 * Note that this is safe to call from any thread.
 */
WASM_API_EXTERN void wasmtime_interrupt_handle_interrupt(wasmtime_interrupt_handle_t *handle);

/**
 * \brief Attempts to extract a WASI-specific exit status from this trap.
 *
 * Returns `true` if the trap is a WASI "exit" trap and has a return status. If
 * `true` is returned then the exit status is returned through the `status`
 * pointer. If `false` is returned then this is not a wasi exit trap.
 */
WASM_API_EXTERN bool wasmtime_trap_exit_status(const wasm_trap_t*, int *status);

/**
 * \brief Returns a human-readable name for this frame's function.
 *
 * This function will attempt to load a human-readable name for function this
 * frame points to. This function may return `NULL`.
 *
 * The lifetime of the returned name is the same as the #wasm_frame_t itself.
 */
WASM_API_EXTERN const wasm_name_t *wasmtime_frame_func_name(const wasm_frame_t*);

/**
 * \brief Returns a human-readable name for this frame's module.
 *
 * This function will attempt to load a human-readable name for module this
 * frame points to. This function may return `NULL`.
 *
 * The lifetime of the returned name is the same as the #wasm_frame_t itself.
 */
WASM_API_EXTERN const wasm_name_t *wasmtime_frame_module_name(const wasm_frame_t*);

/**
 * \brief Call a WebAssembly function.
 *
 * This function is similar to #wasm_func_call, but with a few tweaks:
 *
 * * `args` and `results` have a size parameter saying how big the arrays are
 * * An error *and* a trap can be returned
 * * Errors are returned if `args` have the wrong types, if the args/results
 *   arrays have the wrong lengths, or if values come from the wrong store.
 *
 * The are three possible return states from this function:
 *
 * 1. The returned error is non-null. This means `results`
 *    wasn't written to and `trap` will have `NULL` written to it. This state
 *    means that programmer error happened when calling the function (e.g. the
 *    size of the args/results were wrong)
 * 2. The trap pointer is filled in. This means the returned error is `NULL` and
 *    `results` was not written to. This state means that the function was
 *    executing but hit a wasm trap while executing.
 * 3. The error and trap returned are both `NULL` and `results` are written to.
 *    This means that the function call worked and the specified results were
 *    produced.
 *
 * The `trap` pointer cannot be `NULL`. The `args` and `results` pointers may be
 * `NULL` if the corresponding length is zero.
 *
 * Does not take ownership of `wasm_val_t` arguments. Gives ownership of
 * `wasm_val_t` results.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_func_call(
    wasm_func_t *func,
    const wasm_val_t *args,
    size_t num_args,
    wasm_val_t *results,
    size_t num_results,
    own wasm_trap_t **trap
);

/**
 * \brief Creates a new global value.
 *
 * Similar to #wasm_global_new, but with a few tweaks:
 *
 * * An error is returned instead of #wasm_global_t, which is taken as an
 *   out-parameter
 * * An error happens when the `type` specified does not match the type of the
 *   value `val`, or if it comes from a different store than `store`.
 *
 * This function does not take ownership of any of its arguments but returned
 * values are owned by the caller.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_global_new(
    wasm_store_t *store,
    const wasm_globaltype_t *type,
    const wasm_val_t *val,
    own wasm_global_t **ret
);

/**
 * \brief Sets a global to a new value.
 *
 * This function is the same as #wasm_global_set, except in the case of an error
 * a #wasmtime_error_t is returned.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_global_set(
    wasm_global_t *global,
    const wasm_val_t *val
);

/**
 * \brief Wasmtime-specific function to instantiate a module.
 *
 * This function is similar to #wasm_instance_new, but with a few tweaks:
 *
 * * An error message can be returned from this function.
 * * The number of imports specified is passed as an argument
 * * The `trap` pointer is required to not be NULL.
 *
 * The states of return values from this function are similar to
 * #wasmtime_func_call where an error can be returned meaning something like a
 * link error in this context. A trap can be returned (meaning no error or
 * instance is returned), or an instance can be returned (meaning no error or
 * trap is returned).
 *
 * This function does not take ownership of any of its arguments, but all return
 * values are owned by the caller.
 *
 * See #wasm_instance_new for information about how to fill in the `imports`
 * array.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_instance_new(
    wasm_store_t *store,
    const wasm_module_t *module,
    const wasm_extern_t* const imports[],
    size_t num_imports,
    own wasm_instance_t **instance,
    own wasm_trap_t **trap
);

/**
 * \brief Wasmtime-specific function to compile a module.
 *
 * This function will compile a WebAssembly binary into an owned #wasm_module_t.
 * This performs the same as #wasm_module_new except that it returns a
 * #wasmtime_error_t type to get richer error information.
 *
 * On success the returned #wasmtime_error_t is `NULL` and the `ret` pointer is
 * filled in with a #wasm_module_t. On failure the #wasmtime_error_t is
 * non-`NULL` and the `ret` pointer is unmodified.
 *
 * This function does not take ownership of any of its arguments, but the
 * returned error and module are owned by the caller.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_module_new(
    wasm_engine_t *engine,
    const wasm_byte_vec_t *binary,
    own wasm_module_t **ret
);

/**
 * \brief Wasmtime-specific function to validate a module.
 *
 * This function will validate the provided byte sequence to determine if it is
 * a valid WebAssembly binary. This function performs the same as
 * #wasm_module_validate except that it returns a #wasmtime_error_t which
 * contains an error message if validation fails.
 *
 * This function does not take ownership of its arguments but the caller is
 * expected to deallocate the returned error if it is non-`NULL`.
 *
 * If the binary validates then `NULL` is returned, otherwise the error returned
 * describes why the binary did not validate.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_module_validate(
    wasm_store_t *store,
    const wasm_byte_vec_t *binary
);


/**
 * \brief Creates a new host-defined wasm table.
 *
 * This function is the same as #wasm_table_new except that it's specialized for
 * funcref tables by taking a `wasm_func_t` initialization value. Additionally
 * it returns errors via #wasmtime_error_t.
 *
 * This function does not take ownership of any of its parameters, but yields
 * ownership of returned values (the table and error).
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_funcref_table_new(
    wasm_store_t *store,
    const wasm_tabletype_t *element_ty,
    wasm_func_t *init,
    own wasm_table_t **table
);

/**
 * \brief Gets a value in a table.
 *
 * This function is the same as #wasm_table_get except that it's specialized for
 * funcref tables by returning a `wasm_func_t` value. Additionally a `bool`
 * return value indicates whether the `index` provided was in bounds.
 *
 * This function does not take ownership of any of its parameters, but yields
 * ownership of returned #wasm_func_t.
 */
WASM_API_EXTERN bool wasmtime_funcref_table_get(
    const wasm_table_t *table,
    wasm_table_size_t index,
    own wasm_func_t **func
);

/**
 * \brief Sets a value in a table.
 *
 * This function is similar to #wasm_table_set, but has a few differences:
 *
 * * An error is returned through #wasmtime_error_t describing erroneous
 *   situations.
 * * The value being set is specialized to #wasm_func_t.
 *
 * This function does not take ownership of any of its parameters, but yields
 * ownership of returned #wasmtime_error_t.
 */
WASM_API_EXTERN own wasmtime_error_t *wasmtime_funcref_table_set(
    wasm_table_t *table,
    wasm_table_size_t index,
    const wasm_func_t *value
);

/**
 * \brief Grows a table.
 *
 * This function is similar to #wasm_table_grow, but has a few differences:
 *
 * * An error is returned through #wasmtime_error_t describing erroneous
 *   situations.
 * * The initialization value is specialized to #wasm_func_t.
 * * The previous size of the table is returned through `prev_size`.
 *
 * This function does not take ownership of any of its parameters, but yields
 * ownership of returned #wasmtime_error_t.
 */
WASM_API_EXTERN wasmtime_error_t *wasmtime_funcref_table_grow(
    wasm_table_t *table,
    wasm_table_size_t delta,
    const wasm_func_t *init,
    wasm_table_size_t *prev_size
);

/**
 * \brief Create a new `externref` value.
 *
 * Creates a new `externref` value wrapping the provided data, and writes it to
 * `valp`.
 *
 * This function does not take an associated finalizer to clean up the data when
 * the reference is reclaimed. If you need a finalizer to clean up the data,
 * then use #wasmtime_externref_new_with_finalizer.
 *
 * Gives ownership of the newly created `externref` value.
 */
WASM_API_EXTERN void wasmtime_externref_new(own void *data, wasm_val_t *valp);

/**
 * \brief A finalizer for an `externref`'s wrapped data.
 *
 * A finalizer callback to clean up an `externref`'s wrapped data after the
 * `externref` has been reclaimed. This is an opportunity to run destructors,
 * free dynamically allocated memory, close file handles, etc.
 */
typedef void (*wasmtime_externref_finalizer_t)(void*);

/**
 * \brief Create a new `externref` value with a finalizer.
 *
 * Creates a new `externref` value wrapping the provided data, and writes it to
 * `valp`.
 *
 * When the reference is reclaimed, the wrapped data is cleaned up with the
 * provided finalizer. If you do not need to clean up the wrapped data, then use
 * #wasmtime_externref_new.
 *
 * Gives ownership of the newly created `externref` value.
 */
WASM_API_EXTERN void wasmtime_externref_new_with_finalizer(
    own void *data,
    wasmtime_externref_finalizer_t finalizer,
    wasm_val_t *valp
);

/**
 * \brief Get an `externref`'s wrapped data
 *
 * If the given value is a reference to a non-null `externref`, writes the
 * wrapped data that was passed into #wasmtime_externref_new or
 * #wasmtime_externref_new_with_finalizer when creating the given `externref` to
 * `datap`, and returns `true`.
 *
 * If the value is a reference to a null `externref`, writes `NULL` to `datap`
 * and returns `true`.
 *
 * If the given value is not an `externref`, returns `false` and leaves `datap`
 * unmodified.
 *
 * Does not take ownership of `val`. Does not give up ownership of the `void*`
 * data written to `datap`.
 *
 * Both `val` and `datap` must not be `NULL`.
 */
WASM_API_EXTERN bool wasmtime_externref_data(wasm_val_t* val, void** datap);

#undef own

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // WASMTIME_API_H
